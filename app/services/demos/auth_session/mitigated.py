"""Mitigated implementations demonstrating secure session rotation (CWE-384 defense),
server-side session invalidation on logout (CWE-613 defense), and secure cookie attributes.
"""

import secrets

from . import (
    LAB_AUTH_SESSION_CONTRACT_SUMMARY,
    LAB_AUTH_SESSION_USER_EMAIL,
    LAB_AUTH_SESSION_USER_NAME,
    LAB_AUTH_SESSION_USER_ROLE,
    LABEL_ACCESS_DENIED,
    LABEL_SESSION_REVOKED,
    SessionInspectionResult,
    SyntheticLoginResult,
    SyntheticLogoutResult,
    SyntheticSessionRecord,
)
from .store import get_pre_auth_token, get_session, set_session


def execute_mitigated_login(pre_token: str) -> SyntheticLoginResult:
    """Simulate user login with secure session rotation and secure cookie attributes."""
    # Defense 1: Invalidate / detach pre-authentication token
    old_record = get_session(pre_token)
    if old_record is not None:
        old_record.is_authenticated = False
        old_record.is_revoked = True
        set_session(old_record)

    # Defense 2: Issue a brand new cryptographically random session token
    new_token = f"AUTH-SESSION-{secrets.token_hex(16)}"
    new_record = SyntheticSessionRecord(
        token=new_token,
        is_authenticated=True,
        user_email=LAB_AUTH_SESSION_USER_EMAIL,
        display_name=LAB_AUTH_SESSION_USER_NAME,
        role=LAB_AUTH_SESSION_USER_ROLE,
        contract_summary=LAB_AUTH_SESSION_CONTRACT_SUMMARY,
        is_revoked=False,
        rotated_from=pre_token,
        # Defense 3: Secure cookie flags
        cookie_httponly=True,
        cookie_samesite="Lax",
    )
    set_session(new_record)

    return SyntheticLoginResult(
        success=True,
        pre_auth_token=pre_token,
        effective_token=new_token,
        session_rotated=True,
        cookie_httponly=True,
        cookie_samesite="Lax",
        evidence_summary=(
            "Mitigated mode rotated the session identifier on authentication, issuing a new "
            "cryptographically secure token and invalidating the pre-authentication token. "
            "The pre-auth token cannot be used to access the authenticated session."
        ),
        classification="SESSION ROTATION APPLIED (DEFENDED AGAINST FIXATION)",
    )


def execute_mitigated_logout(token: str) -> SyntheticLogoutResult:
    """Simulate user logout with explicit server-side session invalidation."""
    record = get_session(token)
    if record is not None:
        record.is_authenticated = False
        record.is_revoked = True
        set_session(record)

    return SyntheticLogoutResult(
        token=token,
        server_invalidated=True,
        message=(
            "The server invalidated and revoked the session token server-side. "
            "Replaying this token will be rejected with HTTP 401."
        ),
        classification="SERVER-SIDE SESSION INVALIDATION APPLIED",
    )


def execute_mitigated_inspect(token: str) -> SessionInspectionResult:
    """Inspect what access a given synthetic session token grants in mitigated mode."""
    record = get_session(token)
    pre_auth_token = get_pre_auth_token()

    # Case 1: Attacker tests the pre-authentication token after login
    if token == pre_auth_token:
        return SessionInspectionResult(
            token=token,
            is_authenticated=False,
            user_email=None,
            display_name=None,
            is_revoked=True,
            status_code=401,
            status_label=LABEL_ACCESS_DENIED,
            message=(
                f"{LABEL_ACCESS_DENIED}: Session rotation invalidated the pre-authentication token. "
                "The attacker cannot access Alex Rivers' account or synthetic contracts."
            ),
            simulated_account_takeover=False,
        )

    # Case 2: Token is revoked (e.g. after logout)
    if record is not None and record.is_revoked:
        return SessionInspectionResult(
            token=token,
            is_authenticated=False,
            user_email=None,
            display_name=None,
            is_revoked=True,
            status_code=401,
            status_label=LABEL_SESSION_REVOKED,
            message=(
                f"{LABEL_SESSION_REVOKED}: The session token was invalidated on logout. "
                "Replaying discarded credentials was rejected by the server."
            ),
            simulated_account_takeover=False,
        )

    # Case 3: Active authenticated rotated session
    if record is not None and record.is_authenticated and not record.is_revoked:
        return SessionInspectionResult(
            token=token,
            is_authenticated=True,
            user_email=record.user_email,
            display_name=record.display_name,
            is_revoked=False,
            status_code=200,
            status_label="AUTHENTICATED ACCESS",
            message=f"Session token is valid and authenticated as {record.display_name}.",
            simulated_account_takeover=False,
        )

    # Case 4: Unknown / unauthenticated token
    return SessionInspectionResult(
        token=token,
        is_authenticated=False,
        user_email=None,
        display_name=None,
        is_revoked=False,
        status_code=401,
        status_label="UNAUTHENTICATED SESSION",
        message="Token is unauthenticated. Access denied.",
        simulated_account_takeover=False,
    )
