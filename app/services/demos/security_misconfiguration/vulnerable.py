"""Vulnerable implementation of the Security Misconfiguration demonstration.

Simulates verbose error disclosure (CWE-209), exposed diagnostic endpoint (CWE-215),
and insecure response headers (CWE-16) using purely synthetic fixtures.
Operates exclusively when the centralized lab safety gate is open.
"""

import uuid
from typing import Final

from app.services.demos.security_misconfiguration import (
    ERROR_CASE_KEYS,
    DebugStatusResult,
    ErrorDisclosureResult,
)
from app.services.demos.security_misconfiguration.synthetic_data import (
    SYNTHETIC_DEBUG_STATUS_PAYLOAD,
    SYNTHETIC_ENV_FIXTURES,
    SYNTHETIC_ERROR_MESSAGES,
    SYNTHETIC_ERROR_TITLES,
    SYNTHETIC_STACK_TRACES,
)


VULNERABLE_CLASSIFICATION: Final[str] = (
    "VULNERABLE: Verbose internal traceback and synthetic environment disclosures exposed"
)


def execute_vulnerable_error(error_type: str) -> ErrorDisclosureResult:
    """Simulate unhandled escrow failure with verbose diagnostic stack trace disclosure.

    In vulnerable mode, unhandled application errors expose full synthetic internal
    stack traces, synthetic framework versions, and synthetic mock environment variables.
    """
    selected_error = error_type if error_type in ERROR_CASE_KEYS else "divide_by_zero"
    incident_id = f"SYNTH-ERR-{uuid.uuid4().hex[:8].upper()}"

    return ErrorDisclosureResult(
        status_code=500,
        incident_id=incident_id,
        error_type=selected_error,
        is_verbose=True,
        error_title=SYNTHETIC_ERROR_TITLES[selected_error],
        error_message=SYNTHETIC_ERROR_MESSAGES[selected_error],
        synthetic_stack_trace=list(SYNTHETIC_STACK_TRACES[selected_error]),
        synthetic_env_info=dict(SYNTHETIC_ENV_FIXTURES),
        classification=VULNERABLE_CLASSIFICATION,
    )


def get_vulnerable_debug_status() -> DebugStatusResult:
    """Return diagnostic status information with exposed internal topology details.

    In vulnerable mode, the diagnostic endpoint responds with full synthetic environment
    and service topology information, along with revealing debug headers.
    """
    return DebugStatusResult(
        status_code=200,
        is_exposed=True,
        status_data=dict(SYNTHETIC_DEBUG_STATUS_PAYLOAD),
        headers={
            "X-Debug-Mode": "Enabled",
            "X-Powered-By": "SecureHire-Synthetic-Lab-Daemon/1.0",
        },
        message=(
            "VULNERABLE: Diagnostic endpoint exposed internal synthetic topology, "
            "connection strings, and framework versions."
        ),
    )
