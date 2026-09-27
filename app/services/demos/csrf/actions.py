"""State changes restricted to the one seeded synthetic CSRF proposal."""

from dataclasses import dataclass

from ....extensions import db
from ....models import Proposal
from ...marketplace import MarketplaceError, change_proposal_status


@dataclass(frozen=True)
class FixtureActionResult:
    state_before: str
    state_after: str
    changed: bool


def accept_fixture_proposal(proposal: Proposal) -> FixtureActionResult:
    before = proposal.status
    if before != "pending":
        return FixtureActionResult(before, before, False)
    try:
        change_proposal_status(proposal, "accepted")
    except MarketplaceError:
        db.session.rollback()
        current = db.session.get(Proposal, proposal.id)
        state = current.status if current is not None else before
        return FixtureActionResult(before, state, False)
    return FixtureActionResult(before, "accepted", True)


def reset_fixture_proposal(proposal: Proposal) -> bool:
    """Reset only the fixed fixture through a separate CSRF-protected endpoint."""
    if proposal.status == "pending":
        return False
    proposal.status = "pending"
    db.session.commit()
    return True
