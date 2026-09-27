"""Mitigated Clickjacking service providing structured anti-framing evidence."""

from datetime import datetime, timezone

from . import MITIGATED_FRAME_ANCESTORS, MITIGATED_X_FRAME_OPTIONS


def get_mitigated_clickjacking_evidence() -> dict[str, object]:
    """Generate structured inspection evidence for mitigated anti-framing protection."""
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "effective_mode": "mitigated",
        "x_frame_options": MITIGATED_X_FRAME_OPTIONS,
        "csp_frame_ancestors": MITIGATED_FRAME_ANCESTORS,
        "framing_permitted": False,
        "browser_behavior": (
            "The browser inspects X-Frame-Options: DENY and CSP frame-ancestors 'none'. "
            "It refuses to render the page inside any <frame>, <iframe>, <embed>, or <object>."
        ),
        "expected_behavior": (
            "Anti-framing headers prevent UI redressing attacks. Modern browsers block "
            "framing from both external origins and same-origin frames when 'none' is specified."
        ),
        "observed_behavior": (
            f"Protected: Endpoint serves X-Frame-Options: {MITIGATED_X_FRAME_OPTIONS} "
            f"and Content-Security-Policy: {MITIGATED_FRAME_ANCESTORS}. Framing is blocked."
        ),
        "mitigation_status": "PROTECTED - Anti-framing headers enforced.",
        "timestamp": now_iso,
    }
