"""Bounded synthetic search content used only by the Reflected XSS demo."""
from dataclasses import dataclass

@dataclass(frozen=True)
class SyntheticSearchResult:
    title: str
    category: str
    description: str

REFLECTED_XSS_FIXTURES = (
    SyntheticSearchResult("Python Automation Helper", "Development", "Synthetic gig for a small Python data-cleaning tool."),
    SyntheticSearchResult("Secure Flask Marketplace Prototype", "Web Development", "Synthetic gig for a local Flask and Python prototype."),
    SyntheticSearchResult("Accessible Portfolio Refresh", "Design", "Synthetic gig for an accessible portfolio page."),
)

def search_local_content(search_term: str) -> list[SyntheticSearchResult]:
    """Search only the fixed local fixtures with case-insensitive substring matching."""
    needle = search_term.casefold()
    return [item for item in REFLECTED_XSS_FIXTURES if any(
        needle in value.casefold() for value in (item.title, item.category, item.description)
    )]
