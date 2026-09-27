"""Clickjacking demonstration services for the Security Lab."""

from typing import Final

CLICKJACKING_DEMO_TITLE: Final[str] = "Synthetic Freelancer Skill Endorsement"
CLICKJACKING_DEMO_DESCRIPTION: Final[str] = (
    "A 1-click synthetic action modeled after freelance skill endorsements. "
    "Demonstrates how invisible framing overlays can trick users into clicking buttons."
)

MITIGATED_X_FRAME_OPTIONS: Final[str] = "DENY"
MITIGATED_FRAME_ANCESTORS: Final[str] = "frame-ancestors 'none'"
VULNERABLE_FRAME_ANCESTORS: Final[str] = "frame-ancestors 'self'"

DECOY_BUTTON_LABEL: Final[str] = "Claim $100 Freelancer Bonus!"
REAL_BUTTON_LABEL: Final[str] = "Endorse Freelancer Skill"
