"""Reflected XSS behavior, gate, isolation, and evidence tests."""

from markupsafe import escape

from app.extensions import db
from app.models import Gig, LabRun, SecurityMode
from app.services.demos.reflected_xss import APPROVED_REFLECTED_XSS_PAYLOAD
from app.services.demos.reflected_xss.content import REFLECTED_XSS_FIXTURES
from conftest import csrf_token, login_as, make_user

PAYLOAD = APPROVED_REFLECTED_XSS_PAYLOAD


def authenticated_client(app, email="reflected@example.test"):
    make_user(app, email, "freelancer")
    client = app.test_client()
    login_as(client, email)
    return client


def set_reflected_mode(app, mode="vulnerable"):
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="reflected_xss").one_or_none()
        if setting is None:
            db.session.add(SecurityMode(vulnerability_key="reflected_xss", mode=mode))
        else:
            setting.mode = mode
        db.session.commit()


def run_demo(client, search_term, *, mode_field=None, query_string="", headers=None):
    token = csrf_token(client, "/security-lab/reflected-xss")
    data = {"csrf_token": token, "search_term": search_term}
    if mode_field is not None:
        data["mode"] = mode_field
    return client.post(
        "/security-lab/reflected-xss" + query_string,
        data=data,
        headers=headers,
    )


def test_python_search_returns_synthetic_content_in_mitigated_mode(app):
    client = authenticated_client(app)
    response = run_demo(client, "Python")
    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert b"Python Automation Helper" in response.data
    assert b"Secure Flask Marketplace Prototype" in response.data
    assert b"SAFE SEARCH REFLECTION" in response.data
    assert len(REFLECTED_XSS_FIXTURES) == 3
    with app.app_context():
        run = LabRun.query.one()
        assert run.mode == "mitigated" and run.result == "passed"


def test_ordinary_search_input_is_reflected_in_mitigated_response(app):
    client = authenticated_client(app)
    response = run_demo(client, "Python")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'id="reflected-xss-output"' in text
    assert ">Python</div>" in text
    assert "Response reflected input" in text and "Timestamp (UTC)" in text
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_approved_payload_is_encoded_as_text_and_not_executable_in_mitigated_mode(app):
    client = authenticated_client(app)
    response = run_demo(client, PAYLOAD)
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert str(escape(PAYLOAD)) in text
    assert PAYLOAD not in text
    assert "APPROVED PAYLOAD ENCODED AS TEXT" in text
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_vulnerable_mode_is_blocked_when_lab_flag_is_false(app):
    client = authenticated_client(app)
    set_reflected_mode(app)
    app.config["LAB_ENABLE"] = False
    response = run_demo(client, PAYLOAD)
    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert str(escape(PAYLOAD)).encode() in response.data
    assert PAYLOAD.encode() not in response.data
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_vulnerable_mode_is_blocked_outside_allowed_environment(app):
    client = authenticated_client(app)
    set_reflected_mode(app)
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "production"})
    response = run_demo(client, PAYLOAD)
    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert str(escape(PAYLOAD)).encode() in response.data
    assert PAYLOAD.encode() not in response.data
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_vulnerable_mode_is_blocked_for_non_loopback_access(app):
    client = authenticated_client(app)
    set_reflected_mode(app)
    app.config["LAB_ENABLE"] = True
    token = csrf_token(client, "/security-lab/reflected-xss")
    response = client.post(
        "/security-lab/reflected-xss",
        data={"csrf_token": token, "search_term": PAYLOAD},
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert response.status_code == 403
    assert PAYLOAD.encode() not in response.data
    with app.app_context():
        assert LabRun.query.count() == 0


def test_vulnerable_mode_requires_all_gate_conditions_and_reflects_approved_payload(app):
    client = authenticated_client(app)
    set_reflected_mode(app)
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    response = run_demo(client, PAYLOAD)
    assert response.status_code == 200
    assert b"Effective mode: VULNERABLE" in response.data
    assert PAYLOAD.encode() in response.data
    assert b"APPROVED SCRIPT MARKUP REFLECTED WITHOUT ENCODING" in response.data
    assert b"LOCALHOST ONLY" in response.data
    assert "script-src 'self' 'unsafe-inline'" in response.headers["Content-Security-Policy"]
    with app.app_context():
        run = LabRun.query.one()
        assert run.mode == "vulnerable" and run.result == "passed"
        assert "payload" not in LabRun.__table__.columns
        assert PAYLOAD not in repr(run)

    ordinary = run_demo(client, "Python")
    assert b"Effective mode: VULNERABLE" in ordinary.data
    assert b"ORDINARY INPUT REFLECTED WITHOUT ENCODING" in ordinary.data
    assert b"Python</div>" in ordinary.data
    assert "unsafe-inline" not in ordinary.headers["Content-Security-Policy"]


def test_client_supplied_mode_values_cannot_enable_vulnerable_rendering(app):
    client = authenticated_client(app)
    app.config["LAB_ENABLE"] = True
    client.set_cookie("mode", "vulnerable")
    response = run_demo(
        client, PAYLOAD, mode_field="vulnerable", query_string="?mode=vulnerable",
        headers={"X-SecureHire-Mode": "vulnerable"},
    )
    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert str(escape(PAYLOAD)).encode() in response.data
    assert PAYLOAD.encode() not in response.data
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="reflected_xss").one()
        assert setting.mode == "mitigated"
        assert LabRun.query.one().mode == "mitigated"
        assert "payload" not in LabRun.__table__.columns


def test_normal_marketplace_search_stays_safe_when_lab_mode_is_vulnerable(app):
    owner_id = make_user(app, "marketplace-owner@example.test", "buyer")
    with app.app_context():
        db.session.add(Gig(
            owner_id=owner_id, title="Python marketplace project",
            description="Synthetic marketplace gig for normal search isolation.",
            category="Development", budget="100.00", status="open",
        ))
        db.session.commit()
    client = authenticated_client(app, "reflected-market@example.test")
    set_reflected_mode(app)
    app.config["LAB_ENABLE"] = True
    response = client.get("/gigs", query_string={"q": PAYLOAD})
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert PAYLOAD not in text and str(escape(PAYLOAD)) in text
    assert "Python marketplace project" not in text
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
    with app.app_context():
        assert LabRun.query.count() == 0


def test_other_security_lab_pages_keep_the_default_csp(app):
    client = authenticated_client(app)
    set_reflected_mode(app)
    app.config["LAB_ENABLE"] = True
    vulnerable = run_demo(client, PAYLOAD)
    stored = client.get("/security-lab/stored-xss")
    sqli = client.get("/security-lab/sqli")
    assert "unsafe-inline" in vulnerable.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in stored.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in sqli.headers["Content-Security-Policy"]
