"""Vulnerable Clickjacking service demonstrating omitted anti-framing headers."""

from datetime import datetime, timezone

from ...security_modes import vulnerable_mode_gate_open


def get_vulnerable_clickjacking_evidence() -> dict[str, object]:
    """Generate structured inspection evidence for the vulnerable framing demonstration."""
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    gate_open = vulnerable_mode_gate_open()

    return {
        "effective_mode": "vulnerable" if gate_open else "mitigated",
        "x_frame_options": "OMITTED (None)",
        "csp_frame_ancestors": "OMITTED (Allows framing)",
        "framing_permitted": gate_open,
        "browser_behavior": (
            "Because X-Frame-Options and CSP frame-ancestors are omitted on this response, "
            "the browser permits rendering this endpoint inside an <iframe>."
        ),
        "expected_behavior": (
            "In an unhardened web application, omitted anti-framing headers allow an attacker's "
            "website to load the target action in a transparent <iframe> under a decoy button lure."
        ),
        "observed_behavior": (
            "Vulnerable Mode Active: Anti-framing headers are omitted for this target endpoint. "
            "The controlled framing simulator can successfully embed and display the target."
        ),
        "mitigation_status": (
            "VULNERABLE - Anti-framing headers omitted for demonstration (strictly gate-controlled)."
        ),
        "timestamp": now_iso,
    }
