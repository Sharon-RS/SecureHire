"""Intentionally vulnerable, fixture-bounded IDOR/BOLA read path.

This module demonstrates object-level authorization failure. It is reachable
only through the central server-side lab gate and reads only the two fixed
synthetic proposal fixtures. It never changes marketplace state.
"""

from .scenario import find_scenario_proposal, project_proposal


def read_proposal_vulnerable(target_proposal_id: int, allowed_proposals: list):
    """Deliberately omit requester ownership authorization for the selected fixture."""
    proposal = find_scenario_proposal(target_proposal_id, allowed_proposals)
    if proposal is None:
        return None
    # Intentionally vulnerable: the reference is fixture-bounded, but no
    # comparison is made between proposal.freelancer_id and the requester.
    return project_proposal(proposal)
