"""Constants and dataclasses for the isolated synthetic Authentication / Session Security lab."""

from dataclasses import dataclass
from typing import Final


AUTH_SESSION_DEMO_TITLE: Final[str] = "Synthetic Freelancer Session Lifecycle & Fixation Lab"
AUTH_SESSION_DEMO_DESCRIPTION: Final[str] = (
    "A safe, isolated demonstration modeling session fixation, session invalidation on logout, "
    "and cookie security attributes on a simulated shared freelance kiosk."
)

# Synthetic persona: strictly isolated synthetic consultant data
LAB_AUTH_SESSION_USER_EMAIL: Final[str] = "alex.freelancer@example.test"
LAB_AUTH_SESSION_USER_NAME: Final[str] = "Alex Rivers (Synthetic Security Consultant)"
LAB_AUTH_SESSION_USER_ROLE: Final[str] = "freelancer"
LAB_AUTH_SESSION_CONTRACT_SUMMARY: Final[str] = (
    "Synthetic Escrow Balance: $2,450.00 | Active Contracts: 2 (Audit Proposal #104, PenTest #109)"
)

# Synthetic pre-authentication session token (the trap token on a shared kiosk)
INITIAL_PRE_AUTH_TOKEN: Final[str] = "PRE-AUTH-GUEST-SESSION-TOKEN-DEMO-001"
AUTH_SESSION_COOKIE_NAME: Final[str] = "securehire_demo_session"

# Label required by lab rules
LABEL_SIMULATED_TAKEOVER: Final[str] = "SIMULATED ACCOUNT TAKEOVER"
LABEL_ACCESS_DENIED: Final[str] = "ACCESS DENIED (Session Invalid or Rotated)"
LABEL_SESSION_REVOKED: Final[str] = "SESSION REVOKED (Server-Side Invalidation)"
LABEL_STALE_SESSION_REPLAY: Final[str] = "STALE SESSION REPLAY SUCCESSFUL (Server Failed to Invalidate)"


@dataclass
class SyntheticSessionRecord:
    """Represents a session record in the completely isolated synthetic lab store."""

    token: str
    is_authenticated: bool = False
    user_email: str | None = None
    display_name: str | None = None
    role: str | None = None
    contract_summary: str | None = None
    is_revoked: bool = False
    rotated_from: str | None = None
    cookie_httponly: bool = True
    cookie_samesite: str = "Lax"


@dataclass(frozen=True)
class SyntheticLoginResult:
    """Result of simulating login in either vulnerable or mitigated mode."""

    success: bool
    pre_auth_token: str
    effective_token: str
    session_rotated: bool
    cookie_httponly: bool
    cookie_samesite: str | None
    evidence_summary: str
    classification: str


@dataclass(frozen=True)
class SessionInspectionResult:
    """Result of inspecting what access a given synthetic session token grants."""

    token: str
    is_authenticated: bool
    user_email: str | None
    display_name: str | None
    is_revoked: bool
    status_code: int
    status_label: str
    message: str
    simulated_account_takeover: bool


@dataclass(frozen=True)
class SyntheticLogoutResult:
    """Result of simulating logout in either vulnerable or mitigated mode."""

    token: str
    server_invalidated: bool
    message: str
    classification: str
