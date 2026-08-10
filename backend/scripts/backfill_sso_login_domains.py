"""Backfill the cloud SSO login-domain routing catalog.

Domain routing is projected from each provider's allowed_email_domains on
provider save. Providers configured before routing shipped have no projection
until they are re-saved, so run this once after deploy to project them all.

Usage (kubernetes):
    kubectl exec -it <api-pod> -- python -m scripts.backfill_sso_login_domains
"""

import os
import sys

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)

from ee.onyx.db.tenant_sso_domain import (  # noqa: E402
    reconcile_login_domain_routing,
)
from onyx.db.engine.sql_engine import SqlEngine  # noqa: E402
from onyx.utils.logger import setup_logger  # noqa: E402

logger = setup_logger()


def main() -> None:
    SqlEngine.init_engine(pool_size=5, max_overflow=2)
    logger.info("Reconciling SSO login-domain routing across all workspaces")
    reconcile_login_domain_routing()
    logger.info("Done")


if __name__ == "__main__":
    main()
