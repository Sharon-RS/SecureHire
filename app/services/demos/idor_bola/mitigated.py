"""Object-authorized IDOR/BOLA implementation for the lab's synthetic fixture."""

from dataclasses import dataclass

from .scenario import find_scenario_proposal, project_proposal


@dataclass(frozen=True)
class ProposalReadDecision:
    allowed: bool
    proposal: dict[str, object] | None


def read_proposal_mitigated(
    target_proposal_id: int,
    requester_id: int,
    allowed_proposals: list,
) -> ProposalReadDecision:
    """Return proposal fields only after checking ownership against the session user."""
    proposal = find_scenario_proposal(target_proposal_id, allowed_proposals)
    if proposal is None or proposal.freelancer_id != requester_id:
        return ProposalReadDecision(allowed=False, proposal=None)
    return ProposalReadDecision(allowed=True, proposal=project_proposal(proposal))
