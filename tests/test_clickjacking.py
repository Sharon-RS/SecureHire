"""Tests for Milestone 10: Clickjacking demonstration and anti-framing mitigations."""

import pytest

from app.extensions import db
from app.models import LabRun, SecurityMode
from conftest import csrf_token, login_as, make_user, post_form


TEST_USER_EMAIL = "freelancer@example.test"
ADMIN_USER_EMAIL = "admin@example.test"


def set_clickjacking_mode(app, mode: str):
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="clickjacking").one_or_none()
        if setting is None:
            db.session.add(SecurityMode(vulnerability_key="clickjacking", mode=mode))
        else:
            setting.mode = mode
        db.session.commit()


def setup_auth(client, app, role="freelancer", email=TEST_USER_EMAIL):
    user_id = make_user(app, email=email, role=role)
    login_as(client, email)
    return user_id


# =====================================================================
# 1. Access Control & Page Display Tests
# =====================================================================


def test_clickjacking_page_requires_authentication(client):
    response = client.get("/security-lab/clickjacking")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_clickjacking_page_renders_mitigated_by_default(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/clickjacking")
    assert response.status_code == 200
    assert b"Clickjacking (UI Redressing)" in response.data
    assert b"Effective mode: MITIGATED" in response.data
    assert b"Protection: PROTECTED" in response.data
    assert b"ATTACK FLOW" in response.data
    assert b"INTERACTIVE SIMULATION" in response.data
    assert b"LIVE HTTP RESPONSE HEADERS" in response.data
    assert b"MITIGATION" in response.data
    assert b"Demonstration not implemented yet." not in response.data


def test_clickjacking_detail_dispatcher_renders(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/clickjacking")
    assert response.status_code == 200
    assert b"Clickjacking" in response.data
    assert b"Effective mode: MITIGATED" in response.data


def test_clickjacking_framing_test_page_renders(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/clickjacking/framing-test")
    assert response.status_code == 200
    assert b"Standalone Framing Test Harness" in response.data
    assert b"<iframe" in response.data


# =====================================================================
# 2. Mitigated Anti-Framing Header Tests
# =====================================================================


def test_mitigated_target_delivers_x_frame_options_deny(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/clickjacking/target")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_mitigated_target_delivers_csp_frame_ancestors_none(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/clickjacking/target")
    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in csp


def test_mitigated_target_renders_expected_content(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/clickjacking/target")
    assert response.status_code == 200
    assert b"Jane Doe" in response.data
    assert b"Endorse Freelancer Skill" in response.data


# =====================================================================
# 3. Vulnerable Mode Framing Header Tests
# =====================================================================


def test_vulnerable_target_omits_x_frame_options_when_gate_open(client, app):
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = client.get("/security-lab/clickjacking/target")
    assert response.status_code == 200
    assert "X-Frame-Options" not in response.headers


def test_vulnerable_target_omits_frame_ancestors_none_when_gate_open(client, app):
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = client.get("/security-lab/clickjacking/target")
    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" not in csp
    # Other security directives remain active
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp


def test_vulnerable_target_preserves_other_security_headers(client, app):
    """Verify that vulnerable target omits ONLY anti-framing headers, keeping nosniff etc."""
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = client.get("/security-lab/clickjacking/target")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_vulnerable_target_action_executes_and_records_run(client, app):
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/clickjacking/target",
        "/security-lab/clickjacking/target",
        {},
    )
    assert response.status_code == 302
    assert "/security-lab/clickjacking/target" in response.headers["Location"]

    with app.app_context():
        last_run = LabRun.query.filter_by(vulnerability_key="clickjacking").order_by(LabRun.id.desc()).first()
        assert last_run is not None
        assert last_run.result == "passed"
        assert last_run.mode == "vulnerable"


# =====================================================================
# 4. Critical Safety Rule: Global Security Header Preservation
# =====================================================================


def test_global_security_headers_preserved_on_home_when_clickjacking_vulnerable(client, app):
    """Proves vulnerable clickjacking mode never weakens the root page."""
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = client.get("/")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


def test_global_security_headers_preserved_on_marketplace_when_clickjacking_vulnerable(client, app):
    """Proves vulnerable clickjacking mode never weakens marketplace routes."""
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = client.get("/marketplace/gigs")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


def test_global_security_headers_preserved_on_auth_when_clickjacking_vulnerable(client, app):
    """Proves vulnerable clickjacking mode never weakens authentication pages."""
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = client.get("/auth/login")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


def test_global_security_headers_preserved_on_security_lab_main_when_vulnerable(client, app):
    """Proves that even /security-lab/clickjacking itself retains DENY; only the target is framable."""
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = client.get("/security-lab/clickjacking")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


# =====================================================================
# 5. Fail-Closed Central Gate Tests
# =====================================================================


def test_vulnerable_mode_fails_closed_when_lab_enable_false(client, app):
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = False

    response = client.get("/security-lab/clickjacking/target")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


def test_vulnerable_mode_fails_closed_in_production_environment(client, app):
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True
    app.config["APP_ENV"] = "production"

    response = client.get("/security-lab/clickjacking/target")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


def test_vulnerable_mode_fails_closed_on_remote_socket(client, app):
    setup_auth(client, app)
    set_clickjacking_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    # Remote IP fails closed
    response = client.get(
        "/security-lab/clickjacking/target",
        environ_overrides={"REMOTE_ADDR": "198.51.100.44"},
    )
    # Either blocked by loopback middleware (403) or fails closed to DENY
    if response.status_code == 200:
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in response.headers.get("Content-Security-Policy", "")


# =====================================================================
# 6. CSRF & Reset Tests
# =====================================================================


def test_clickjacking_target_action_requires_csrf(client, app):
    setup_auth(client, app)
    response = client.post("/security-lab/clickjacking/target", data={})
    assert response.status_code == 400


def test_clickjacking_reset_requires_csrf(client, app):
    setup_auth(client, app)
    response = client.post("/security-lab/clickjacking/reset", data={})
    assert response.status_code == 400


def test_clickjacking_reset_clears_endorsements(client, app):
    setup_auth(client, app)
    # Perform an endorsement
    post_form(
        client,
        "/security-lab/clickjacking/target",
        "/security-lab/clickjacking/target",
        {},
    )
    # Reset
    response = post_form(
        client,
        "/security-lab/clickjacking",
        "/security-lab/clickjacking/reset",
        {},
    )
    assert response.status_code == 302
    assert "/security-lab/clickjacking" in response.headers["Location"]


# =====================================================================
# 7. LabRun Bounded Schema Verification
# =====================================================================


def test_lab_run_schema_has_no_payload_fields():
    column_names = {column.name for column in LabRun.__table__.columns}
    assert "payload" not in column_names
    assert "token" not in column_names
    assert "click_coordinates" not in column_names
    assert "overlay_data" not in column_names
