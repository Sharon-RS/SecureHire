"""Intentionally unsafe reflection for the gated Reflected XSS lab only."""
from markupsafe import Markup

def render_vulnerable_reflection(search_term: str) -> Markup:
    """Mark the exact approved local proof of concept as HTML for the demo.

    This deliberately bypasses output encoding. The caller restricts raw rendering
    to the harmless proof of concept on the isolated loopback-gated lab route.
    Never use this renderer for marketplace input.
    """
    return Markup(search_term)
