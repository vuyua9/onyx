"""Prove a workspace controls an email domain by publishing a DNS TXT record.

Domain routing auto-provisions strangers on a domain, so a workspace must show
it owns the domain first. Only whoever controls the domain's DNS can publish the
record we look for, so finding it is that proof. Verifying flips the catalog row
that lets the domain route; a scheduled re-check drops routing if the record
later disappears.
"""

import hashlib
import hmac

import dns.resolver
from dns.exception import DNSException

from ee.onyx.db.tenant_sso_domain import is_claimed_domain, mark_domain_verified
from onyx.configs.app_configs import USER_AUTH_SECRET
from onyx.db.sso_provider import is_valid_email_domain
from onyx.error_handling.error_codes import OnyxErrorCode
from onyx.error_handling.exceptions import OnyxError
from onyx.utils.logger import setup_logger

logger = setup_logger()

# Published under the claimed domain at this host, kept off the apex so it never
# collides with the domain's SPF or other TXT records.
VERIFICATION_HOST = "_onyx-verification"
_VALUE_PREFIX = "onyx-verify="
# Bounds a slow or unreachable resolver so it can't tie up the request.
_DNS_TIMEOUT_SECONDS = 5.0


def _domain_token(tenant_id: str, domain: str) -> str:
    """A stable per-(workspace, domain) token. Bound to the workspace so one
    tenant's published record cannot verify another's claim, and unguessable so
    only someone who can read the DNS zone knows what to publish."""
    message = f"sso-domain:{tenant_id}:{domain}".encode()
    digest = hmac.new(USER_AUTH_SECRET.encode(), message, hashlib.sha256)
    return digest.hexdigest()[:32]


def verification_record(tenant_id: str, domain: str) -> tuple[str, str]:
    """(host, value) of the TXT record the admin publishes to prove control."""
    domain = domain.strip().lower()
    host = f"{VERIFICATION_HOST}.{domain}"
    return host, f"{_VALUE_PREFIX}{_domain_token(tenant_id, domain)}"


def verify_domain_via_dns(tenant_id: str, domain: str) -> bool:
    """Resolve the TXT record and verify the domain on a match. Returns whether
    the record was found. A miss is expected while DNS is still propagating."""
    domain = domain.strip().lower()
    if not is_valid_email_domain(domain):
        raise OnyxError(
            OnyxErrorCode.INVALID_INPUT, "That is not a valid email domain."
        )
    if not is_claimed_domain(tenant_id, domain):
        raise OnyxError(
            OnyxErrorCode.NOT_FOUND,
            "Save the provider with this domain before verifying it.",
        )

    host, expected = verification_record(tenant_id, domain)
    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT_SECONDS
    resolver.lifetime = _DNS_TIMEOUT_SECONDS
    try:
        answers = resolver.resolve(host, "TXT")
    except DNSException:
        # NXDOMAIN, no TXT answer, or timeout: the record is not visible yet.
        return False

    for record in answers:
        # A TXT record is one or more quoted chunks, joined before matching.
        value = b"".join(record.strings).decode(errors="ignore").strip()
        if hmac.compare_digest(value, expected):
            mark_domain_verified(tenant_id, domain)
            return True
    return False
