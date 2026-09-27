"""Mitigated SQL injection search using SQLAlchemy-bound ORM expressions."""

from sqlalchemy import or_, select

from ....extensions import db
from ....models import LabGigFixture
from . import MAX_RESULTS


def search_gigs_mitigated(search_term: str) -> list[dict[str, object]]:
    """Return exact title/category matches; user input is always a bound literal."""
    statement = (
        select(LabGigFixture)
        .where(
            or_(
                LabGigFixture.title == search_term,
                LabGigFixture.category == search_term,
            )
        )
        .order_by(LabGigFixture.id.asc())
        .limit(MAX_RESULTS)
    )
    fixtures = db.session.execute(statement).scalars().all()
    return [
        {
            "id": fixture.id,
            "title": fixture.title,
            "category": fixture.category,
            "description": fixture.description,
        }
        for fixture in fixtures
    ]
