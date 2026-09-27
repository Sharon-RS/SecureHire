"""Marketplace repository helpers."""

from sqlalchemy import or_

from ..models import Gig, Proposal, Review


def find_gig(gig_id: int) -> Gig | None:
    return Gig.query.filter_by(id=gig_id).first()


def search_open_gigs(query: str | None = None) -> list[Gig]:
    statement = Gig.query.filter_by(status="open")
    term = (query or "").strip()
    if term:
        statement = statement.filter(
            or_(
                Gig.title.contains(term, autoescape=True),
                Gig.description.contains(term, autoescape=True),
                Gig.category.contains(term, autoescape=True),
            )
        )
    return statement.order_by(Gig.created_at.desc(), Gig.id.desc()).limit(100).all()


def find_proposal(proposal_id: int) -> Proposal | None:
    return Proposal.query.filter_by(id=proposal_id).first()


def proposals_for_gig(gig_id: int) -> list[Proposal]:
    return (
        Proposal.query.filter_by(gig_id=gig_id)
        .order_by(Proposal.created_at.desc(), Proposal.id.desc())
        .all()
    )


def proposals_for_freelancer(freelancer_id: int) -> list[Proposal]:
    return (
        Proposal.query.filter_by(freelancer_id=freelancer_id)
        .order_by(Proposal.created_at.desc(), Proposal.id.desc())
        .all()
    )



def find_review_for_reviewer(proposal_id: int, reviewer_id: int) -> Review | None:
    return Review.query.filter_by(
        proposal_id=proposal_id, reviewer_id=reviewer_id
    ).one_or_none()


def reviews_for_gig(gig_id: int) -> list[Review]:
    return (
        Review.query.join(Proposal)
        .filter(Proposal.gig_id == gig_id)
        .order_by(Review.created_at.desc(), Review.id.desc())
        .all()
    )
