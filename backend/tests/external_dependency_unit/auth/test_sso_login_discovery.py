"""Guard the cloud SSO discovery contract.

Discovery runs before the visitor has authenticated, so it must answer only
about workspaces the address already belongs to, must not accept an invitation
on their behalf, and must not distinguish "no such workspace" from "workspace
without SSO" in what it returns.
"""

from collections.abc import Generator
from typing import Any, cast
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Table, delete, inspect, select
from sqlalchemy.orm import Session

from ee.onyx.auth.sso_domain_verification import (
    confirm_domain_verification,
    send_domain_verification_code,
)
from ee.onyx.db.tenant_sso_domain import (
    claim_email_domains,
    is_routable_email_domain,
    lookup_tenant_id_for_email_domain,
)
from ee.onyx.db.user_tenant_mapping import lookup_tenant_id_for_login
from onyx.auth.sso_tenant_token import (
    decode_sso_tenant_token,
    generate_sso_tenant_token,
)
from onyx.db.models import TenantSSODomain, UserTenantMapping
from onyx.error_handling.error_codes import OnyxErrorCode
from onyx.error_handling.exceptions import OnyxError, register_onyx_exception_handlers
from onyx.server.sso_discovery import router as sso_discovery_router

_TEST_SECRET = "test-user-auth-secret-at-least-32-bytes-long"


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    app = FastAPI()
    register_onyx_exception_handlers(app)
    app.include_router(sso_discovery_router)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def catalog_session(db_session: Session) -> Generator[Session, None, None]:
    """`user_tenant_mapping` lives in the multi-tenant catalog migrations, which
    a single-tenant dev database never runs. Create it for the test and leave a
    real catalog untouched."""
    bind = db_session.get_bind()
    table = cast(Table, UserTenantMapping.__table__)
    created_here = not inspect(bind).has_table(table.name, schema="public")
    if created_here:
        table.create(bind=bind)
        db_session.commit()
    try:
        yield db_session
    finally:
        if created_here:
            db_session.rollback()
            table.drop(bind=bind)
            db_session.commit()


def _new_email() -> str:
    return f"discovery-{uuid4().hex[:10]}@example.com"


def _add_mapping(session: Session, email: str, tenant_id: str, active: bool) -> None:
    session.add(UserTenantMapping(email=email, tenant_id=tenant_id, active=active))
    session.commit()


def _cleanup(session: Session, email: str) -> None:
    session.execute(delete(UserTenantMapping).where(UserTenantMapping.email == email))
    session.commit()


def _mapping_active(session: Session, email: str) -> bool:
    session.expire_all()
    return bool(
        session.scalar(
            select(UserTenantMapping.active).where(UserTenantMapping.email == email)
        )
    )


@patch("ee.onyx.db.user_tenant_mapping.MULTI_TENANT", True)
def test_lookup_does_not_accept_a_pending_invitation(
    catalog_session: Session,
) -> None:
    """An unauthenticated lookup that flipped `active` would enroll someone in a
    workspace by typing their address into a login form."""
    email = _new_email()
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    _add_mapping(catalog_session, email, tenant_id, active=False)
    try:
        assert lookup_tenant_id_for_login(email) == tenant_id
        assert _mapping_active(catalog_session, email) is False
    finally:
        _cleanup(catalog_session, email)


@patch("ee.onyx.db.user_tenant_mapping.MULTI_TENANT", True)
def test_lookup_refuses_to_choose_between_invitations(
    catalog_session: Session,
) -> None:
    email = _new_email()
    _add_mapping(catalog_session, email, f"tenant_{uuid4().hex[:12]}", active=False)
    _add_mapping(catalog_session, email, f"tenant_{uuid4().hex[:12]}", active=False)
    try:
        assert lookup_tenant_id_for_login(email) is None
    finally:
        _cleanup(catalog_session, email)


@pytest.mark.usefixtures("catalog_session")
@patch("ee.onyx.db.user_tenant_mapping.MULTI_TENANT", True)
def test_lookup_returns_none_for_unknown_address() -> None:
    assert lookup_tenant_id_for_login(_new_email()) is None


@pytest.mark.parametrize(
    "domain,routable",
    [
        ("acme.example", True),
        # A corporate domain that merely contains a consumer-domain word must
        # route. An earlier substring match refused both of these.
        ("livenation.com", True),
        ("deliveroo.co.uk", True),
        ("gmail.com", False),
        ("googlemail.com", False),
        ("outlook.com", False),
        ("proton.me", False),
    ],
)
def test_only_company_domains_route(domain: str, routable: bool) -> None:
    """A shared consumer domain would send every one of its users to whichever
    workspace claimed it first, so it never routes."""
    assert is_routable_email_domain(domain) is routable


@pytest.fixture()
def catalog_with_domains(catalog_session: Session) -> Generator[Session, None, None]:
    """`claim_email_domains` and verification write `tenant_sso_domain`, which a
    single-tenant dev database never creates."""
    bind = catalog_session.get_bind()
    table = cast(Table, TenantSSODomain.__table__)
    created_here = not inspect(bind).has_table(table.name, schema="public")
    if created_here:
        table.create(bind=bind)
        catalog_session.commit()
    try:
        yield catalog_session
    finally:
        if created_here:
            catalog_session.rollback()
            table.drop(bind=bind)
            catalog_session.commit()


class _FakeRedis:
    """Dict-backed stand-in for the tenant Redis client the code path uses."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def set(self, key: str, value: str, **_kwargs: object) -> None:
        self.store[key] = value

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def incr(self, key: str) -> int:
        self.store[key] = str(int(self.store.get(key, "0")) + 1)
        return int(self.store[key])

    def expire(self, key: str, _ttl: int) -> None:
        pass

    def delete(self, *keys: str) -> None:
        for key in keys:
            self.store.pop(key, None)


def _clear_domains(session: Session, tenant_id: str) -> None:
    session.execute(
        delete(TenantSSODomain).where(TenantSSODomain.tenant_id == tenant_id)
    )
    session.commit()


def _sent_code(fake_redis: _FakeRedis, domain: str) -> str:
    return fake_redis.store[f"sso_domain_verify:{domain}"]


@patch("ee.onyx.db.tenant_sso_domain.MULTI_TENANT", True)
def test_claim_records_a_pending_unverified_domain(
    catalog_with_domains: Session,
) -> None:
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    domain = f"acme-{uuid4().hex[:8]}.example"
    try:
        claim_email_domains(tenant_id, [domain])
        catalog_with_domains.expire_all()
        row = catalog_with_domains.get(TenantSSODomain, (tenant_id, domain))
        assert row is not None
        assert row.verified_at is None
    finally:
        _clear_domains(catalog_with_domains, tenant_id)


@patch("ee.onyx.db.tenant_sso_domain.MULTI_TENANT", True)
def test_unverified_domain_does_not_route(catalog_with_domains: Session) -> None:
    """A claim proves nothing until verified, so it must not route anyone."""
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    domain = f"acme-{uuid4().hex[:8]}.example"
    try:
        claim_email_domains(tenant_id, [domain])
        assert lookup_tenant_id_for_email_domain(f"user@{domain}") is None
    finally:
        _clear_domains(catalog_with_domains, tenant_id)


@patch("ee.onyx.db.tenant_sso_domain.MULTI_TENANT", True)
def test_email_verification_marks_verified_and_routes(
    catalog_with_domains: Session,
) -> None:
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    domain = f"acme-{uuid4().hex[:8]}.example"
    fake_redis = _FakeRedis()
    try:
        claim_email_domains(tenant_id, [domain])
        with (
            patch(
                "ee.onyx.auth.sso_domain_verification.get_redis_client",
                return_value=fake_redis,
            ),
            patch(
                "ee.onyx.auth.sso_domain_verification.get_shared_redis_client",
                return_value=fake_redis,
            ),
            patch("ee.onyx.auth.sso_domain_verification.send_email") as mock_send,
        ):
            recipient = send_domain_verification_code(tenant_id, domain, "admin")
            assert recipient == f"admin@{domain}"
            assert mock_send.called
            code = _sent_code(fake_redis, domain)
            assert confirm_domain_verification(tenant_id, domain, code) is True
        assert lookup_tenant_id_for_email_domain(f"user@{domain}") == tenant_id
    finally:
        _clear_domains(catalog_with_domains, tenant_id)


@patch("ee.onyx.db.tenant_sso_domain.MULTI_TENANT", True)
def test_email_verification_burns_the_code_after_repeated_wrong_tries(
    catalog_with_domains: Session,
) -> None:
    """A guessable code is only safe if wrong tries run out, so the sixth is
    refused and the domain stays unverified."""
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    domain = f"acme-{uuid4().hex[:8]}.example"
    fake_redis = _FakeRedis()
    try:
        claim_email_domains(tenant_id, [domain])
        with (
            patch(
                "ee.onyx.auth.sso_domain_verification.get_redis_client",
                return_value=fake_redis,
            ),
            patch(
                "ee.onyx.auth.sso_domain_verification.get_shared_redis_client",
                return_value=fake_redis,
            ),
            patch("ee.onyx.auth.sso_domain_verification.send_email"),
        ):
            send_domain_verification_code(tenant_id, domain, "postmaster")
            for _ in range(5):
                assert (
                    confirm_domain_verification(tenant_id, domain, "wrong-code")
                    is False
                )
            with pytest.raises(OnyxError):
                confirm_domain_verification(tenant_id, domain, "wrong-code")
        assert lookup_tenant_id_for_email_domain(f"user@{domain}") is None
    finally:
        _clear_domains(catalog_with_domains, tenant_id)


@patch("ee.onyx.db.tenant_sso_domain.MULTI_TENANT", True)
def test_send_code_refuses_a_non_role_mailbox(catalog_with_domains: Session) -> None:
    """The address is built from the claimed domain, but the local part must be a
    role mailbox, so a code can't be sent to an arbitrary inbox."""
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    domain = f"acme-{uuid4().hex[:8]}.example"
    fake_redis = _FakeRedis()
    try:
        claim_email_domains(tenant_id, [domain])
        with (
            patch(
                "ee.onyx.auth.sso_domain_verification.get_redis_client",
                return_value=fake_redis,
            ),
            patch(
                "ee.onyx.auth.sso_domain_verification.get_shared_redis_client",
                return_value=fake_redis,
            ),
            patch("ee.onyx.auth.sso_domain_verification.send_email") as mock_send,
        ):
            with pytest.raises(OnyxError):
                send_domain_verification_code(tenant_id, domain, "ceo")
            assert not mock_send.called
    finally:
        _clear_domains(catalog_with_domains, tenant_id)


@patch("ee.onyx.db.tenant_sso_domain.MULTI_TENANT", True)
def test_send_code_is_rate_limited_per_domain(
    catalog_with_domains: Session,
) -> None:
    """Each send is a fresh code, so resends are capped to keep the code from
    being ground down and the role mailbox from being spammed."""
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    domain = f"acme-{uuid4().hex[:8]}.example"
    fake_redis = _FakeRedis()
    try:
        claim_email_domains(tenant_id, [domain])
        with (
            patch(
                "ee.onyx.auth.sso_domain_verification.get_redis_client",
                return_value=fake_redis,
            ),
            patch(
                "ee.onyx.auth.sso_domain_verification.get_shared_redis_client",
                return_value=fake_redis,
            ),
            patch("ee.onyx.auth.sso_domain_verification.send_email"),
        ):
            for _ in range(10):
                send_domain_verification_code(tenant_id, domain, "admin")
            with pytest.raises(OnyxError):
                send_domain_verification_code(tenant_id, domain, "admin")
    finally:
        _clear_domains(catalog_with_domains, tenant_id)


@patch("onyx.server.sso_discovery.MULTI_TENANT", True)
@patch("onyx.server.sso_discovery._enforce_discovery_rate_limit", new=AsyncMock())
def test_unknown_address_returns_an_empty_list(client: TestClient) -> None:
    """Same shape an SSO-less workspace returns, so the response cannot be used
    to tell whether an address belongs to a customer."""
    response = client.post("/auth/sso/discover", json={"email": _new_email()})
    assert response.status_code == 200
    assert response.json() == {"providers": []}


def test_malformed_address_is_rejected(client: TestClient) -> None:
    response = client.post("/auth/sso/discover", json={"email": "not-an-email"})
    assert response.status_code == 422


@patch("onyx.server.sso_discovery.MULTI_TENANT", True)
@patch(
    "onyx.server.sso_discovery.get_async_redis_connection",
    side_effect=ConnectionError("redis is down"),
)
def test_lookup_refuses_when_the_limiter_is_unavailable(
    _redis: object, client: TestClient
) -> None:
    """The limiter is the only bound on probing this endpoint, so losing it has
    to cost the lookup rather than the bound."""
    response = client.post("/auth/sso/discover", json={"email": _new_email()})
    assert response.status_code == OnyxErrorCode.RATE_LIMITED.status_code


def test_workspace_pin_round_trips_and_rejects_another_signer() -> None:
    """The pin decides which workspace's IdP configuration a login reads, so a
    token this deployment did not sign must not select one."""
    tenant_id = f"tenant_{uuid4().hex[:12]}"

    with patch("onyx.auth.sso_tenant_token.USER_AUTH_SECRET", _TEST_SECRET):
        token = generate_sso_tenant_token(tenant_id)
        assert decode_sso_tenant_token(token) == tenant_id

    # Same token, a different signing secret. Flipping a character instead would
    # be flaky: base64url characters can differ while the decoded bytes match.
    with patch("onyx.auth.sso_tenant_token.USER_AUTH_SECRET", _TEST_SECRET + "x"):
        with pytest.raises(OnyxError):
            decode_sso_tenant_token(token)


@patch("onyx.auth.sso_tenant_token.USER_AUTH_SECRET", _TEST_SECRET)
@patch("onyx.server.sso_discovery.MULTI_TENANT", True)
@patch("onyx.server.sso_discovery._enforce_discovery_rate_limit", new=AsyncMock())
def test_resolved_workspace_authorize_urls_carry_a_workspace_pin(
    client: TestClient,
) -> None:
    """Authorize has no session to read the workspace from, so discovery has to
    hand it over in the URL it returns."""
    tenant_id = f"tenant_{uuid4().hex[:12]}"
    fake_provider: Any = type(
        "FakeProvider",
        (),
        {
            "name": "okta",
            "display_name": "Okta",
            "provider_type": "OIDC",
        },
    )()

    with (
        patch(
            "onyx.server.sso_discovery.fetch_ee_implementation_or_noop",
            return_value=lambda _email: tenant_id,
        ),
        patch("onyx.server.sso_discovery.get_session_with_tenant"),
        patch(
            "onyx.server.sso_discovery.fetch_sso_providers",
            return_value=[fake_provider],
        ),
    ):
        response = client.post("/auth/sso/discover", json={"email": _new_email()})

    assert response.status_code == 200
    [provider] = response.json()["providers"]
    assert provider["authorize_url"].startswith("/api/auth/oidc/okta/authorize?")
    assert "workspace_token=" in provider["authorize_url"]
