"""Marketplace write operations and state transitions."""

from decimal import Decimal

from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import Gig, Proposal


class MarketplaceError(Exception):
    """Raised when a marketplace operation violates a business rule."""


def create_gig(owner_id: int, *, title: str, description: str, category: str, budget: Decimal) -> Gig:
    gig = Gig(
        owner_id=owner_id,
        title=title.strip(),
        description=description.strip(),
        category=category.strip(),
        budget=budget,
        status="open",
    )
    db.session.add(gig)
    db.session.commit()
    return gig


def submit_proposal(
    gig: Gig,
    freelancer_id: int,
    *,
    cover_letter: str,
    proposed_price: Decimal,
    timeline: str,
) -> Proposal:
    # Lock the parent row so closing a gig and submitting a proposal serialize on MySQL.
    locked_gig = (
        db.session.query(Gig)
        .filter_by(id=gig.id)
        .populate_existing()
        .with_for_update()
        .first()
    )
    if locked_gig is None or locked_gig.status != "open":
        raise MarketplaceError("This gig is closed.")
    proposal = Proposal(
        gig_id=locked_gig.id,
        freelancer_id=freelancer_id,
        cover_letter=cover_letter.strip(),
        proposed_price=proposed_price,
        timeline=timeline.strip(),
        status="pending",
    )
    db.session.add(proposal)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise MarketplaceError("You have already submitted a proposal for this gig.") from exc
    return proposal


def change_proposal_status(proposal: Proposal, status: str) -> None:
    if status not in {"accepted", "rejected"}:
        raise MarketplaceError("Choose an available proposal decision.")

    # All decisions for a gig lock the same parent first, preventing two accepted proposals.
    locked_gig = (
        db.session.query(Gig)
        .filter_by(id=proposal.gig_id)
        .populate_existing()
        .with_for_update()
        .first()
    )
    locked_proposal = (
        db.session.query(Proposal)
        .filter_by(id=proposal.id)
        .populate_existing()
        .with_for_update()
        .first()
    )
    if locked_gig is None or locked_proposal is None:
        raise MarketplaceError("The gig or proposal no longer exists.")
    if locked_proposal.status != "pending":
        raise MarketplaceError("Only pending proposals can be updated.")
    if status == "accepted":
        another_accepted = Proposal.query.filter(
            Proposal.gig_id == locked_gig.id,
            Proposal.status == "accepted",
            Proposal.id != locked_proposal.id,
        ).first()
        if another_accepted:
            raise MarketplaceError("Another proposal has already been accepted for this gig.")
    locked_proposal.status = status
    db.session.commit()


def close_gig(gig: Gig) -> None:
    locked_gig = (
        db.session.query(Gig)
        .filter_by(id=gig.id)
        .populate_existing()
        .with_for_update()
        .first()
    )
    if locked_gig is None or locked_gig.status != "open":
        raise MarketplaceError("This gig is already closed.")
    locked_gig.status = "closed"
    db.session.commit()
