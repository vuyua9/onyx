"""Prove a workspace controls an email domain by receiving a code on it.

Domain routing auto-provisions strangers on a domain, so a workspace must show
it owns the domain first. Receiving a code at a role mailbox (postmaster@,
admin@) is that proof: only someone who runs the domain reads those. The code
lives in Redis with a short life and a small attempt cap, so it cannot be
guessed, and verifying flips the catalog row that lets the domain route.
"""

import html
import secrets

from ee.onyx.db.tenant_sso_domain import is_claimed_domain, mark_domain_verified
from onyx.auth.email_utils import send_email
from onyx.db.sso_provider import is_valid_email_domain
from onyx.error_handling.error_codes import OnyxErrorCode
from onyx.error_handling.exceptions import OnyxError
from onyx.redis.redis_pool import (
    TenantRedisClient,
    get_redis_client,
    get_shared_redis_client,
)
from onyx.utils.logger import setup_logger

logger = setup_logger()

# Role mailboxes whoever runs the domain's mail controls, so reaching one is
# evidence of control. webmaster@/hostmaster@ are excluded as often delegated to a
# web or DNS host. The recipient is always built from the claimed domain.
ALLOWED_ROLE_MAILBOXES = ("admin", "postmaster")

_CODE_TTL_SECONDS = 15 * 60
_MAX_ATTEMPTS = 5
# Each send is a fresh random code, so a send cap keeps it from being ground down
# over many resends. The per-workspace cap bounds guesses, the domain-global cap
# keeps many workspaces from each spamming the same mailbox.
_MAX_SENDS = 10
_MAX_GLOBAL_SENDS = 50
_SEND_WINDOW_SECONDS = 60 * 60
_REDIS_KEY = "sso_domain_verify:{domain}"
_ATTEMPTS_KEY = "sso_domain_verify:{domain}:attempts"
_SENDS_KEY = "sso_domain_verify:{domain}:sends"
_GLOBAL_SENDS_KEY = "sso_domain_verify:{domain}:sends_all"


def _generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _enforce_send_rate_limit(redis: TenantRedisClient, key: str, limit: int) -> None:
    count = redis.incr(key)
    if count == 1:
        redis.expire(key, _SEND_WINDOW_SECONDS)
    if count > limit:
        raise OnyxError(
            OnyxErrorCode.RATE_LIMITED,
            "Too many codes sent for this domain recently. Try again later.",
        )


def send_domain_verification_code(
    tenant_id: str, domain: str, mailbox_prefix: str
) -> str:
    """Email a fresh code to a role mailbox on the domain. Returns the address it
    was sent to. Overwrites any code in flight, so a resend invalidates the old
    one and resets the attempt count."""
    domain = domain.strip().lower()
    if not is_valid_email_domain(domain):
        raise OnyxError(
            OnyxErrorCode.INVALID_INPUT, "That is not a valid email domain."
        )
    if mailbox_prefix not in ALLOWED_ROLE_MAILBOXES:
        raise OnyxError(
            OnyxErrorCode.INVALID_INPUT,
            "Choose one of the standard role mailboxes to receive the code.",
        )
    if not is_claimed_domain(tenant_id, domain):
        raise OnyxError(
            OnyxErrorCode.NOT_FOUND, "This workspace has not claimed that domain."
        )

    _enforce_send_rate_limit(
        get_redis_client(tenant_id=tenant_id),
        _SENDS_KEY.format(domain=domain),
        _MAX_SENDS,
    )
    # Bounds total emails to a role mailbox across every workspace claiming the
    # domain, not just this one. The shared client keys outside the tenant namespace.
    _enforce_send_rate_limit(
        get_shared_redis_client(),
        _GLOBAL_SENDS_KEY.format(domain=domain),
        _MAX_GLOBAL_SENDS,
    )

    redis = get_redis_client(tenant_id=tenant_id)
    code = _generate_code()
    redis.set(_REDIS_KEY.format(domain=domain), code, ex=_CODE_TTL_SECONDS)
    redis.delete(_ATTEMPTS_KEY.format(domain=domain))

    recipient = f"{mailbox_prefix}@{domain}"
    subject = f"Verify {domain} for Onyx single sign-on"
    text_body = (
        f"Your verification code for {domain} is {code}.\n\n"
        f"Enter it in Onyx to let anyone on {domain} sign in through your "
        f"workspace's identity provider. The code expires in 15 minutes. If you "
        f"did not request this, you can ignore this email."
    )
    # domain is admin-supplied and unvalidated upstream, so escape it before it
    # lands in the email markup. code is generated digits.
    safe_domain = html.escape(domain)
    html_body = (
        f"<p>Your verification code for <b>{safe_domain}</b> is "
        f"<b style='font-size:1.2em'>{code}</b>.</p>"
        f"<p>Enter it in Onyx to let anyone on {safe_domain} sign in through your "
        f"workspace's identity provider. The code expires in 15 minutes. If you "
        f"did not request this, you can ignore this email.</p>"
    )
    send_email(recipient, subject, html_body, text_body)
    return recipient


def confirm_domain_verification(tenant_id: str, domain: str, code: str) -> bool:
    """Check the submitted code and verify the domain on a match. Returns whether
    the code was correct. A handful of wrong tries burns the code, so it cannot
    be guessed within its life."""
    domain = domain.strip().lower()
    redis = get_redis_client(tenant_id=tenant_id)
    key = _REDIS_KEY.format(domain=domain)
    attempts_key = _ATTEMPTS_KEY.format(domain=domain)

    stored = redis.get(key)
    if stored is None:
        return False

    attempts = redis.incr(attempts_key)
    if attempts == 1:
        redis.expire(attempts_key, _CODE_TTL_SECONDS)
    if attempts > _MAX_ATTEMPTS:
        redis.delete(key)
        redis.delete(attempts_key)
        raise OnyxError(
            OnyxErrorCode.RATE_LIMITED,
            "Too many incorrect codes. Send a new one and try again.",
        )

    stored_code = stored.decode() if isinstance(stored, bytes) else str(stored)
    if not secrets.compare_digest(stored_code, code.strip()):
        return False

    mark_domain_verified(tenant_id, domain)
    redis.delete(key)
    redis.delete(attempts_key)
    return True
