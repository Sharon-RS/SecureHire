"""Storage helpers for per-user Stored XSS lab fixture values."""

from ....extensions import db
from ....models import StoredXssDemoEntry
from . import APPROVED_STORED_XSS_PAYLOAD


def stored_demo_for_user(user_id: int) -> StoredXssDemoEntry | None:
    """Return only the authenticated user's dedicated lab record."""
    return StoredXssDemoEntry.query.filter_by(user_id=user_id).one_or_none()


def store_demo_value(user_id: int, payload: str) -> StoredXssDemoEntry:
    """Persist only the single approved harmless lab payload, once per user."""
    if payload != APPROVED_STORED_XSS_PAYLOAD:
        raise ValueError("Only the approved Stored XSS lab value may be stored.")

    entry = stored_demo_for_user(user_id)
    if entry is None:
        entry = StoredXssDemoEntry(user_id=user_id, payload=payload)
        db.session.add(entry)
    else:
        entry.payload = payload
    db.session.commit()
    return entry
