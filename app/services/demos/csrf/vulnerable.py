"""Intentionally vulnerable CSRF demonstration path.

This function observes token state for bounded evidence but deliberately does
not require a valid token before allowing the fixed synthetic proposal action.
It must only be called by the central-gated Security Lab endpoint.
"""

from . import CsrfTokenDecision
from .token_validation import inspect_submitted_token_state


def accept_without_token_requirement() -> CsrfTokenDecision:
    token_state = inspect_submitted_token_state()
    # Intentional vulnerability: token validation failure is recorded as a
    # bounded label, then ignored for this fixture-only state-changing action.
    return CsrfTokenDecision(token_state=token_state, accepted=True)
