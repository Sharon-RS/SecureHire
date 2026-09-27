"""Intentionally unsafe SQL for the isolated, bounded SQL injection lesson.

This module is used only by the Security Lab route after the centralized safety
gate resolves the stored setting to vulnerable. It selects from the dedicated
synthetic fixture table, permits one harmless proof-of-concept input, has a
static result limit, and performs no writes. Never reuse this code in the
marketplace or any other application feature.
"""

from sqlalchemy import text

from ....extensions import db
from . import MAX_RESULTS


def search_gigs_vulnerable(search_term: str) -> list[dict[str, object]]:
    """Demonstrate how interpolating a search string changes SELECT semantics."""
    statement = text(
        "SELECT id, title, category, description "
        "FROM security_lab_gig_fixtures "
        f"WHERE title = '{search_term}' OR category = '{search_term}' "
        f"ORDER BY id LIMIT {MAX_RESULTS}"
    )
    rows = db.session.execute(statement).mappings().all()
    return [dict(row) for row in rows]
