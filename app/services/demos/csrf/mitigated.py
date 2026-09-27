"""Mitigated CSRF demonstration path using server-side Flask-WTF validation."""

from . import CsrfTokenDecision
from .token_validation import inspect_submitted_token_state


def require_valid_token() -> CsrfTokenDecision:
    token_state = inspect_submitted_token_state()
    return CsrfTokenDecision(token_state=token_state, accepted=(token_state == "valid"))
