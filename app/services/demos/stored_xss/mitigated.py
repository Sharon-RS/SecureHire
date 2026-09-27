"""Context-appropriate output encoding for the Stored XSS lab."""

from markupsafe import Markup, escape


def render_mitigated_demo_value(payload: str) -> Markup:
    """HTML-escape content for its HTML text-node output context."""
    return escape(payload)
