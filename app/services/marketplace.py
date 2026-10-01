from dataclasses import dataclass
from decimal import Decimal

from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import Gig, Proposal, Review


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


def submit_review(
    proposal_id: int,
    reviewer_id: int,
    *,
    rating: int,
    body: str,
) -> Review:
    """Create one review by a participant in an accepted synthetic interaction."""
    proposal = (
        db.session.query(Proposal)
        .filter_by(id=proposal_id)
        .with_for_update()
        .first()
    )
    if proposal is None or proposal.status != "accepted":
        raise MarketplaceError("Only an accepted proposal can be reviewed.")

    if reviewer_id == proposal.gig.owner_id:
        reviewee_id = proposal.freelancer_id
    elif reviewer_id == proposal.freelancer_id:
        reviewee_id = proposal.gig.owner_id
    else:
        raise MarketplaceError("Only participants in this interaction can submit a review.")

    normalized_body = body.strip()
    if reviewer_id == reviewee_id:
        raise MarketplaceError("You cannot review yourself.")
    if not isinstance(rating, int) or rating not in range(1, 6):
        raise MarketplaceError("Choose a rating from 1 to 5.")
    if len(normalized_body) < 3 or len(normalized_body) > 1200:
        raise MarketplaceError("Review text must be between 3 and 1200 characters.")

    review = Review(
        proposal_id=proposal.id,
        reviewer_id=reviewer_id,
        reviewee_id=reviewee_id,
        rating=rating,
        body=normalized_body,
    )
    db.session.add(review)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise MarketplaceError("You have already reviewed this interaction.") from exc
    return review


MAX_SEARCH_QUERY_LENGTH = 100
MAX_CATEGORY_FILTER_LENGTH = 80
MIN_BUDGET_BOUND = Decimal("0.00")
MAX_BUDGET_BOUND = Decimal("99999999.99")


@dataclass(frozen=True)
class MarketplaceFilterCriteria:
    query: str = ""
    category: str = ""
    max_budget: Decimal | None = None

    @classmethod
    def from_params(
        cls,
        query: str | None = None,
        category: str | None = None,
        max_budget_raw: str | None = None,
    ) -> "MarketplaceFilterCriteria":
        clean_query = (query or "").strip()[:MAX_SEARCH_QUERY_LENGTH]
        clean_category = (category or "").strip()[:MAX_CATEGORY_FILTER_LENGTH]

        parsed_budget = None
        if max_budget_raw is not None and str(max_budget_raw).strip() != "":
            try:
                val = Decimal(str(max_budget_raw).strip())
                if MIN_BUDGET_BOUND <= val <= MAX_BUDGET_BOUND:
                    parsed_budget = val
            except (ArithmeticError, ValueError):
                parsed_budget = None

        return cls(
            query=clean_query,
            category=clean_category,
            max_budget=parsed_budget,
        )


def filter_open_gigs(criteria: MarketplaceFilterCriteria) -> list[Gig]:
    """Retrieve open marketplace gigs filtered by validated criteria using parameterized ORM queries."""
    from ..repositories.marketplace import search_open_gigs

    return search_open_gigs(
        query=criteria.query or None,
        category=criteria.category or None,
        max_budget=criteria.max_budget,
    )
