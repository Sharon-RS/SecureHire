"""Server-side resolution of the one proposal reserved for the CSRF lab."""

from ....models import Gig, Proposal, User
from . import (
    LAB_CSRF_BUYER_EMAIL,
    LAB_CSRF_COVER_LETTER,
    LAB_CSRF_FREELANCER_EMAIL,
    LAB_CSRF_GIG_CATEGORY,
    LAB_CSRF_GIG_TITLE,
)


def csrf_scenario_proposal() -> Proposal | None:
    """Find only the exact seeded proposal fixture; callers never supply its ID."""
    buyer = User.query.filter_by(
        email=LAB_CSRF_BUYER_EMAIL,
        role="buyer",
        status="active",
    ).first()
    freelancer = User.query.filter_by(
        email=LAB_CSRF_FREELANCER_EMAIL,
        role="freelancer",
        status="active",
    ).first()
    if buyer is None or freelancer is None:
        return None

    gig = (
        Gig.query.filter_by(
            owner_id=buyer.id,
            title=LAB_CSRF_GIG_TITLE,
            category=LAB_CSRF_GIG_CATEGORY,
            status="closed",
        )
        .order_by(Gig.id.asc())
        .first()
    )
    if gig is None:
        return None

    return (
        Proposal.query.filter_by(
            gig_id=gig.id,
            freelancer_id=freelancer.id,
            cover_letter=LAB_CSRF_COVER_LETTER,
        )
        .order_by(Proposal.id.asc())
        .first()
    )
