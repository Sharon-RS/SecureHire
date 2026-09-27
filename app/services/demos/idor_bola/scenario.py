"""Read-only lookup and bounded projection for the synthetic IDOR/BOLA fixture."""

from ....extensions import db
from ....models import Gig, Proposal, User
from . import (
    LAB_BUYER_EMAIL,
    LAB_FREELANCER_EMAILS,
    LAB_SCENARIO_CATEGORY,
    LAB_SCENARIO_TITLE,
    PERSONA_LABELS,
)


def persona_label_for_email(email: str) -> str:
    """Return a fixed demo alias without exposing account identifiers."""
    return PERSONA_LABELS.get(email, "Synthetic requester")


def scenario_proposals() -> list[Proposal]:
    """Return only the two seeded proposals in the fixed, closed lab gig."""
    buyer = User.query.filter_by(email=LAB_BUYER_EMAIL, role="buyer", status="active").first()
    if buyer is None:
        return []

    freelancers = {
        user.email: user
        for user in User.query.filter(
            User.email.in_(LAB_FREELANCER_EMAILS),
            User.role == "freelancer",
            User.status == "active",
        ).all()
    }
    if len(freelancers) != len(LAB_FREELANCER_EMAILS):
        return []

    gig = (
        Gig.query.filter_by(
            owner_id=buyer.id,
            title=LAB_SCENARIO_TITLE,
            category=LAB_SCENARIO_CATEGORY,
            status="closed",
        )
        .order_by(Gig.id.asc())
        .first()
    )
    if gig is None:
        return []

    proposal_by_freelancer = {
        proposal.freelancer_id: proposal
        for proposal in Proposal.query.filter(
            Proposal.gig_id == gig.id,
            Proposal.freelancer_id.in_([user.id for user in freelancers.values()]),
        ).all()
    }
    if len(proposal_by_freelancer) != len(LAB_FREELANCER_EMAILS):
        return []

    return [
        proposal_by_freelancer[freelancers[email].id]
        for email in LAB_FREELANCER_EMAILS
    ]


def find_scenario_proposal(target_proposal_id: int, allowed_proposals: list[Proposal]):
    """Load an ID only after verifying it belongs to the fixed fixture allowlist."""
    if isinstance(target_proposal_id, bool) or not isinstance(target_proposal_id, int):
        return None
    allowed_ids = {proposal.id for proposal in allowed_proposals}
    if target_proposal_id not in allowed_ids:
        return None
    return db.session.get(Proposal, target_proposal_id)


def project_proposal(proposal: Proposal) -> dict[str, object]:
    """Expose only bounded fields from the synthetic proposal used by the lab."""
    return {
        "proposal_id": proposal.id,
        "gig_title": proposal.gig.title[:140],
        "owner": persona_label_for_email(proposal.freelancer.email),
        "cover_letter": proposal.cover_letter[:180],
        "proposed_price": f"{proposal.proposed_price:.2f}",
        "timeline": proposal.timeline[:80],
        "status": proposal.status,
    }
