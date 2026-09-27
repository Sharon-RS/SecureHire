"""Intentionally unsafe HTML rendering for the gated Stored XSS lab only."""

from markupsafe import Markup


def render_vulnerable_demo_value(payload: str) -> Markup:
    """Mark the stored fixture as trusted markup to demonstrate browser execution.

    This deliberately bypasses output encoding. It is called only by the
    authenticated, loopback-gated Security Lab route for the approved payload.
    Never use this function for marketplace reviews or other user content.
    """
    return Markup(payload)
