"""Context-appropriate HTML text-node encoding for the Reflected XSS lab."""
from markupsafe import Markup, escape

def render_mitigated_reflection(search_term: str) -> Markup:
    """Escape untrusted text before rendering it into an HTML text node."""
    return escape(search_term)
