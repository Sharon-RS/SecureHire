"""Constants for the isolated synthetic CSRF proposal scenario."""

from dataclasses import dataclass


LAB_CSRF_BUYER_EMAIL = "buyer@example.test"
LAB_CSRF_FREELANCER_EMAIL = "lab-freelancer-b@example.test"
LAB_CSRF_GIG_TITLE = "SecureHire CSRF Proposal Fixture"
LAB_CSRF_GIG_CATEGORY = "Security Lab Fixture"
LAB_CSRF_COVER_LETTER = (
    "Synthetic CSRF fixture proposal: a harmless local proposal used to demonstrate "
    "request integrity and proposal acceptance."
)
LAB_CSRF_REQUESTER_LABEL = "Synthetic Buyer"
LAB_CSRF_TARGET_LABEL = "Accept Freelancer B’s synthetic proposal"


@dataclass(frozen=True)
class CsrfTokenDecision:
    token_state: str
    accepted: bool
