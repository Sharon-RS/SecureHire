"""Vulnerable implementations demonstrating Session Fixation (CWE-384),
Insufficient Session Invalidation on Logout (CWE-613), and Insecure Cookie Attributes (CWE-1004).

EDUCATIONAL DEMONSTRATION ONLY:
These implementations intentionally omit session rotation and server-side invalidation.
They operate strictly within the isolated synthetic session store and never affect
normal SecureHire application authentication or sessions.
"""

from . import (
    LAB_AUTH_SESSION_CONTRACT_SUMMARY,
    LAB_AUTH_SESSION_USER_EMAIL,
    LAB_AUTH_SESSION_USER_NAME,
    LAB_AUTH_SESSION_USER_ROLE,
    LABEL_SIMULATED_TAKEOVER,
    LABEL_STALE_SESSION_REPLAY,
    SessionInspectionResult,
    SyntheticLoginResult,
    SyntheticLogoutResult,
    SyntheticSessionRecord,
)
from .store import get_pre_auth_token, get_session, set_session


def execute_vulnerable_login(pre_token: str) -> SyntheticLoginResult:
    """Simulate user login with flawed session fixation (omitting session rotation)."""
    # Flaw: Do NOT generate a new session ID. Reuse pre_token directly.
    record = get_session(pre_token)
    if record is None:
        record = SyntheticSessionRecord(token=pre_token)

    record.is_authenticated = True
    record.user_email = LAB_AUTH_SESSION_USER_EMAIL
    record.display_name = LAB_AUTH_SESSION_USER_NAME
    record.role = LAB_AUTH_SESSION_USER_ROLE
    record.contract_summary = LAB_AUTH_SESSION_CONTRACT_SUMMARY
    record.is_revoked = False
    record.rotated_from = None
    # Flaw: Missing HttpOnly and SameSite flags
    record.cookie_httponly = False
    record.cookie_samesite = "None"

    set_session(record)

    return SyntheticLoginResult(
        success=True,
        pre_auth_token=pre_token,
        effective_token=pre_token,
        session_rotated=False,
        cookie_httponly=False,
        cookie_samesite=None,
        evidence_summary=(
            "Vulnerable mode authenticated the synthetic consultant into the pre-existing session token "
            "without rotating the session identifier. The pre-login token remains valid and authenticated."
        ),
        classification="SESSION FIXATION VULNERABILITY (NO ROTATION)",
    )


def execute_vulnerable_logout(token: str) -> SyntheticLogoutResult:
    """Simulate user logout with flawed session handling (omitting server-side invalidation)."""
    # Flaw: The server fails to revoke the session token in server memory/storage.
    # The record remains is_revoked = False.
    return SyntheticLogoutResult(
        token=token,
        server_invalidated=False,
        message=(
            "Vulnerable logout requested client-side cookie removal, but deliberately omitted "
            "server-side session invalidation. The token remains valid and reusable."
        ),
        classification="INSUFFICIENT SESSION EXPIRATION (SERVER TOKEN PERSISTS)",
    )


def execute_vulnerable_inspect(token: str) -> SessionInspectionResult:
    """Inspect what access a given synthetic session token grants in vulnerable mode."""
    record = get_session(token)
    pre_auth_token = get_pre_auth_token()

    if record is not None and record.is_authenticated and not record.is_revoked:
        if token == pre_auth_token:
            return SessionInspectionResult(
                token=token,
                is_authenticated=True,
                user_email=record.user_email,
                display_name=record.display_name,
                is_revoked=False,
                status_code=200,
                status_label=LABEL_SIMULATED_TAKEOVER,
                message=(
                    f"{LABEL_SIMULATED_TAKEOVER}: Attacker holding the pre-auth kiosk token "
                    f"gained full authenticated access to {record.display_name}'s synthetic contracts "
                    f"and escrow balance without credentials!"
                ),
                simulated_account_takeover=True,
            )

        return SessionInspectionResult(
            token=token,
            is_authenticated=True,
            user_email=record.user_email,
            display_name=record.display_name,
            is_revoked=False,
            status_code=200,
            status_label=LABEL_STALE_SESSION_REPLAY,
            message=(
                f"{LABEL_STALE_SESSION_REPLAY}: The discarded session token was accepted by the server. "
                f"Full access to synthetic account {record.user_email} was restored."
            ),
            simulated_account_takeover=False,
        )

    if record is not None and record.is_revoked:
        return SessionInspectionResult(
            token=token,
            is_authenticated=False,
            user_email=None,
            display_name=None,
            is_revoked=True,
            status_code=401,
            status_label="SESSION REVOKED",
            message="Session token was revoked.",
            simulated_account_takeover=False,
        )

    return SessionInspectionResult(
        token=token,
        is_authenticated=False,
        user_email=None,
        display_name=None,
        is_revoked=False,
        status_code=401,
        status_label="UNAUTHENTICATED GUEST SESSION",
        message="Token is unauthenticated. No user account is bound to this session.",
        simulated_account_takeover=False,
    )
