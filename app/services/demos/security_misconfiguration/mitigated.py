"""Mitigated implementation of the Security Misconfiguration demonstration.

Implements secure error handling with sanitized messages (CWE-209 mitigation),
strictly disabled/forbidden diagnostic endpoints (CWE-215 mitigation),
and hardened response headers (CWE-16 mitigation).
"""

import uuid
from typing import Final

from app.services.demos.security_misconfiguration import (
    ERROR_CASE_KEYS,
    DebugStatusResult,
    ErrorDisclosureResult,
)


MITIGATED_CLASSIFICATION: Final[str] = (
    "MITIGATED: Sanitized generic error response returned. Internal diagnostics suppressed."
)


def execute_mitigated_error(error_type: str) -> ErrorDisclosureResult:
    """Handle simulated escrow failure securely with opaque incident reference.

    In mitigated mode:
    - Internal exceptions are caught and sanitized.
    - An opaque, unique correlation ID is generated for operational tracking.
    - Zero stack traces, file paths, credentials, or runtime versions are exposed to clients.
    """
    selected_error = error_type if error_type in ERROR_CASE_KEYS else "divide_by_zero"
    incident_id = f"INCIDENT-REF-{uuid.uuid4().hex[:8].upper()}"

    return ErrorDisclosureResult(
        status_code=500,
        incident_id=incident_id,
        error_type=selected_error,
        is_verbose=False,
        error_title="An unexpected error occurred while processing the escrow transaction",
        error_message=(
            "The synthetic escrow gateway encountered an unexpected condition. "
            "Our operations team has been notified. Please quote the reference ID "
            "below when contacting support."
        ),
        synthetic_stack_trace=None,
        synthetic_env_info=None,
        classification=MITIGATED_CLASSIFICATION,
    )


def get_mitigated_debug_status() -> DebugStatusResult:
    """Refuse access to internal diagnostic status endpoint.

    In mitigated mode:
    - Diagnostic status endpoints are disabled or restricted (HTTP 403 Forbidden).
    - No revealing headers (such as X-Debug-Mode or X-Powered-By) are returned.
    - Only a generic rejection message with a security reference ID is provided.
    """
    incident_id = f"SEC-DENIED-{uuid.uuid4().hex[:8].upper()}"

    return DebugStatusResult(
        status_code=403,
        is_exposed=False,
        status_data={
            "error": "Forbidden: Diagnostic endpoint is disabled in secure/production mode.",
            "incident_reference": incident_id,
        },
        headers={},
        message=(
            "MITIGATED: Diagnostic endpoint disabled (403 Forbidden). "
            "Internal topology and debug telemetry protected."
        ),
    )
