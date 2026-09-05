#!/usr/bin/python3 -I
"""Isolated entry point for the packaged NorthGate RMM server services."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

PACKAGE_ROOT = "/usr/lib/northgate-rmm-server/site-packages"
ENTRY_POINTS = {
    "northgate-rmm-issuer-service": "northgate_rmm.issuer_service",
    "northgate-rmm-oidc-service": "northgate_rmm.oidc_bridge",
    "northgate-rmm-audit-service": "northgate_rmm.audit_sink",
    "northgate-rmm-audit-export": "northgate_rmm.audit_exporter",
    "northgate-rmm-audit-reconcile": "northgate_rmm.audit_reconcile",
    "northgate-rmm-certificate-status": "northgate_rmm.certificate_status",
    "northgate-rmm-pki-admin": "northgate_rmm.pki_admin",
    "northgate-rmm-recovery": "northgate_rmm.recovery",
    "northgate-rmm-retention": "northgate_rmm.retention",
    "northgate-rmm-admin": "northgate_rmm.admin",
    "northgate-rmm-agent-service": "northgate_rmm.agent_service",
    "northgate-rmm-enrollment-service": "northgate_rmm.enrollment_service",
    "northgate-rmm-operator-service": "northgate_rmm.operator_service",
}


def run() -> int:
    executable = Path(sys.argv[0]).name
    module_name = ENTRY_POINTS.get(executable)
    if module_name is None:
        print(
            "northgate-rmm server launcher rejected its executable name",
            file=sys.stderr,
        )
        return 64
    sys.path.insert(0, PACKAGE_ROOT)
    module = importlib.import_module(module_name)
    return int(module.main())


if __name__ == "__main__":
    raise SystemExit(run())
