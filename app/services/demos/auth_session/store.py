"""Completely isolated, thread-safe in-memory session store for the auth_session lab.

CRITICAL ISOLATION RULE:
This synthetic session store NEVER touches or authenticates Flask-Login, current_user,
the real Flask session, or any normal SecureHire marketplace route.
Tokens in this store are valid ONLY within /security-lab/auth-session/*.
"""

import threading
from typing import Any

from . import (
    INITIAL_PRE_AUTH_TOKEN,
    SyntheticSessionRecord,
)

_LOCK = threading.Lock()
_SESSION_STORE: dict[str, SyntheticSessionRecord] = {}
_CURRENT_PRE_AUTH_TOKEN: str = INITIAL_PRE_AUTH_TOKEN


def _init_default_store() -> None:
    global _CURRENT_PRE_AUTH_TOKEN
    _CURRENT_PRE_AUTH_TOKEN = INITIAL_PRE_AUTH_TOKEN
    _SESSION_STORE.clear()
    _SESSION_STORE[_CURRENT_PRE_AUTH_TOKEN] = SyntheticSessionRecord(
        token=_CURRENT_PRE_AUTH_TOKEN,
        is_authenticated=False,
        user_email=None,
        display_name=None,
        role=None,
        contract_summary=None,
        is_revoked=False,
        rotated_from=None,
        cookie_httponly=True,
        cookie_samesite="Lax",
    )


# Seed initial store
_init_default_store()


def get_pre_auth_token() -> str:
    """Return the currently tracked pre-auth session token (the trap token)."""
    with _LOCK:
        return _CURRENT_PRE_AUTH_TOKEN


def get_session(token: str) -> SyntheticSessionRecord | None:
    """Lookup a synthetic session record by token string."""
    with _LOCK:
        record = _SESSION_STORE.get(token)
        if record is None:
            return None
        # Return a copy to prevent race conditions
        return SyntheticSessionRecord(
            token=record.token,
            is_authenticated=record.is_authenticated,
            user_email=record.user_email,
            display_name=record.display_name,
            role=record.role,
            contract_summary=record.contract_summary,
            is_revoked=record.is_revoked,
            rotated_from=record.rotated_from,
            cookie_httponly=record.cookie_httponly,
            cookie_samesite=record.cookie_samesite,
        )


def set_session(record: SyntheticSessionRecord) -> None:
    """Save or update a synthetic session record in the isolated lab store."""
    with _LOCK:
        _SESSION_STORE[record.token] = record


def get_active_session() -> SyntheticSessionRecord | None:
    """Return the most recently authenticated, unrevoked session if any exists."""
    with _LOCK:
        for record in reversed(list(_SESSION_STORE.values())):
            if record.is_authenticated and not record.is_revoked:
                return record
        return None


def reset_auth_session_store() -> None:
    """Restore the synthetic session store to its pristine initial pre-auth state."""
    with _LOCK:
        _init_default_store()


def get_store_snapshot() -> dict[str, Any]:
    """Return a diagnostic dictionary summarizing all synthetic sessions in the lab."""
    with _LOCK:
        records = [
            {
                "token": rec.token,
                "is_authenticated": rec.is_authenticated,
                "user_email": rec.user_email,
                "display_name": rec.display_name,
                "is_revoked": rec.is_revoked,
                "rotated_from": rec.rotated_from,
                "cookie_httponly": rec.cookie_httponly,
                "cookie_samesite": rec.cookie_samesite,
            }
            for rec in _SESSION_STORE.values()
        ]
        active = next((r for r in records if r["is_authenticated"] and not r["is_revoked"]), None)
        return {
            "pre_auth_token": _CURRENT_PRE_AUTH_TOKEN,
            "session_count": len(_SESSION_STORE),
            "sessions": records,
            "active_session": active,
        }
