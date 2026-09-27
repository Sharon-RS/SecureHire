"""Constants and dataclasses for the isolated synthetic Security Misconfiguration lab."""

from dataclasses import dataclass
from typing import Any, Final


MISCONFIG_DEMO_TITLE: Final[str] = "Synthetic Freelance Escrow Gateway & Misconfiguration Lab"
MISCONFIG_DEMO_DESCRIPTION: Final[str] = (
    "A controlled educational demonstration modeling verbose error disclosure (CWE-209), "
    "exposed diagnostic status endpoints (CWE-215), and insecure default headers (CWE-16) "
    "using exclusively synthetic fixtures."
)

# Supported contract error cases
ERROR_CASES: Final[tuple[tuple[str, str], ...]] = (
    ("divide_by_zero", "Escrow Calculation: Zero-Division Exception (Zero Escrow Rate)"),
    ("invalid_currency", "Payment Gateway: Unhandled Currency Conversion Error"),
    ("connection_timeout", "Contract Ledger: Synthetic Database Connection Timeout"),
)
ERROR_CASE_KEYS: Final[frozenset[str]] = frozenset(k for k, _ in ERROR_CASES)


@dataclass(frozen=True)
class ErrorDisclosureResult:
    """Result of simulating an unhandled contract escrow error."""

    status_code: int
    incident_id: str
    error_type: str
    is_verbose: bool
    error_title: str
    error_message: str
    synthetic_stack_trace: list[str] | None
    synthetic_env_info: dict[str, str] | None
    classification: str


@dataclass(frozen=True)
class DebugStatusResult:
    """Result of querying the diagnostic /debug-status endpoint."""

    status_code: int
    is_exposed: bool
    status_data: dict[str, Any]
    headers: dict[str, str]
    message: str
