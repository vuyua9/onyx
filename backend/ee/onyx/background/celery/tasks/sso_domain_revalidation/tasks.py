"""Cloud SSO: keep login-domain routing from outliving its proof.

Runs per tenant on a schedule. Re-projects the workspace's claimed domains (so a
failed on-save projection self-heals) and drops verification for any verified
domain whose DNS TXT proof no longer resolves.
"""

from celery import shared_task

from ee.onyx.auth.sso_domain_verification import revalidate_tenant_domains
from ee.onyx.db.tenant_sso_domain import reproject_tenant_login_domains
from onyx.configs.app_configs import JOB_TIMEOUT
from onyx.configs.constants import OnyxCeleryTask


@shared_task(
    name=OnyxCeleryTask.REVALIDATE_SSO_DOMAINS_TASK,
    ignore_result=True,
    soft_time_limit=JOB_TIMEOUT,
    trail=False,
)
def revalidate_sso_domains_task(*, tenant_id: str) -> None:
    """Fanned out per tenant by cloud_beat_task_generator."""
    reproject_tenant_login_domains(tenant_id)
    revalidate_tenant_domains(tenant_id)
