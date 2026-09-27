"""Security Misconfiguration lab tests (CWE-209, CWE-215, CWE-16).

Verifies:
- Mitigated mode: sanitized 500 error page with opaque incident ID (no stack traces
  or environment variables), HTTP 403 Forbidden on /debug-status with no revealing headers,
  standard security headers maintained.
- Vulnerable mode: verbose synthetic stack trace and mock environment parameters disclosed
  on simulated unhandled escrow failure (HTTP 500), HTTP 200 with synthetic topology JSON
  and debug headers on /debug-status.
- Fail-closed central safety gate enforcement (LAB_ENABLE=false, non-loopback IP, APP_ENV=production).
- Strict lab authentication boundary preservation: /debug-status requires @login_required
  and is never publicly accessible without authentication.
- Normal application error handlers and routes are completely unaffected and retain full security.
- CSRF protection on lab action forms and bounded LabRun records.
"""

from app.models import LabRun
from app.services.demos.security_misconfiguration.synthetic_data import (
    SYNTHETIC_ENV_FIXTURES,
    SYNTHETIC_LAB_NOTICE,
)
from app.services.security_modes import update_persisted_mode
from conftest import csrf_token, login_as, make_user


def set_misconfig_mode(app, mode: str, admin_id: int):
    with app.app_context():
        update_persisted_mode("security_misconfiguration", mode, admin_id)


def submit_error(client, error_type: str, environ_overrides=None):
    token = csrf_token(client, "/security-lab/security-misconfiguration")
    return client.post(
        "/security-lab/security-misconfiguration/trigger-error",
        data={"error_type": error_type, "csrf_token": token},
        environ_overrides=environ_overrides,
    )


def submit_reset(client):
    token = csrf_token(client, "/security-lab/security-misconfiguration")
    return client.post(
        "/security-lab/security-misconfiguration/reset",
        data={"csrf_token": token},
    )


# ---------------------------------------------------------------------------
# MITIGATED MODE TESTS
# ---------------------------------------------------------------------------


def test_mitigated_error_trigger_returns_sanitized_500(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    response = submit_error(client, "divide_by_zero")
    assert response.status_code == 500
    body = response.get_data(as_text=True)

    # Sanitized response indicators
    assert "INCIDENT-REF-" in body
    assert "Sanitized generic error response returned" in body
    assert "The synthetic escrow gateway encountered an unexpected condition" in body

    # Stack trace and environment disclosures must be absent
    assert "ZeroDivisionError: float division by zero" not in body
    assert "Traceback (most recent call last)" not in body
    assert "/srv/securehire/synthetic_lab/" not in body
    assert SYNTHETIC_ENV_FIXTURES["MOCK_DB_DSN"] not in body
    assert SYNTHETIC_ENV_FIXTURES["MOCK_WORKER_HOST"] not in body

    # Insecure headers must not be present
    assert "Server" not in response.headers or "SecureHire-Synthetic-Lab-Daemon" not in response.headers.get("Server", "")
    assert "X-Debug-Mode" not in response.headers


def test_mitigated_debug_status_returns_403_forbidden(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    response = client.get("/security-lab/security-misconfiguration/debug-status")
    assert response.status_code == 403
    json_data = response.get_json()
    assert json_data is not None
    assert "Forbidden: Diagnostic endpoint is disabled" in json_data.get("error", "")
    assert "SEC-DENIED-" in json_data.get("incident_reference", "")

    # Headers must be stripped
    assert "X-Debug-Mode" not in response.headers
    assert "X-Powered-By" not in response.headers


def test_mitigated_all_error_cases_are_sanitized(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    for error_case in ["invalid_currency", "connection_timeout"]:
        response = submit_error(client, error_case)
        assert response.status_code == 500
        body = response.get_data(as_text=True)
        assert "INCIDENT-REF-" in body
        assert "Sanitized generic error response returned" in body
        assert "KeyError" not in body
        assert "SyntheticTimeoutError" not in body


# ---------------------------------------------------------------------------
# VULNERABLE MODE TESTS
# ---------------------------------------------------------------------------


def test_vulnerable_error_trigger_discloses_stack_trace_and_env(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    response = submit_error(client, "divide_by_zero")
    assert response.status_code == 500
    body = response.get_data(as_text=True)

    # Verbose disclosure assertions
    assert "VULNERABLE: Verbose internal traceback and synthetic environment disclosures exposed" in body
    assert "ZeroDivisionError: float division by zero" in body
    assert "calculate_escrow_fee" in body
    assert "/srv/securehire/synthetic_lab/escrow_calc.py" in body

    # Disclosed synthetic environment parameters
    assert SYNTHETIC_ENV_FIXTURES["MOCK_DB_DSN"] in body
    assert SYNTHETIC_ENV_FIXTURES["MOCK_WORKER_HOST"] in body
    assert SYNTHETIC_ENV_FIXTURES["PYTHON_VERSION"] in body

    # Disclosed headers
    assert response.headers.get("Server") == "SecureHire-Synthetic-Lab-Daemon/1.0"
    assert response.headers.get("X-Debug-Mode") == "Enabled"


def test_vulnerable_debug_status_discloses_topology_json(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    response = client.get("/security-lab/security-misconfiguration/debug-status")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data is not None

    # Verify synthetic topology disclosure
    assert json_data.get("debug_mode") is True
    assert json_data.get("node_id") == SYNTHETIC_ENV_FIXTURES["MOCK_WORKER_HOST"]
    assert json_data.get("internal_ip") == SYNTHETIC_ENV_FIXTURES["MOCK_INTERNAL_IP"]
    assert json_data["synthetic_connections"]["database"] == SYNTHETIC_ENV_FIXTURES["MOCK_DB_DSN"]
    assert json_data.get("disclaimer") == SYNTHETIC_LAB_NOTICE

    # Verify revealing headers
    assert response.headers.get("X-Debug-Mode") == "Enabled"
    assert response.headers.get("X-Powered-By") == "SecureHire-Synthetic-Lab-Daemon/1.0"


def test_vulnerable_other_error_cases(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    # invalid_currency case
    resp_curr = submit_error(client, "invalid_currency")
    assert resp_curr.status_code == 500
    body_curr = resp_curr.get_data(as_text=True)
    assert "KeyError" in body_curr
    assert "Unsupported synthetic currency code: XYZ" in body_curr

    # connection_timeout case
    resp_timeout = submit_error(client, "connection_timeout")
    assert resp_timeout.status_code == 500
    body_timeout = resp_timeout.get_data(as_text=True)
    assert "SyntheticTimeoutError" in body_timeout
    assert "Connection pool exhausted" in body_timeout


# ---------------------------------------------------------------------------
# FAIL-CLOSED SAFETY GATE TESTS
# ---------------------------------------------------------------------------


def test_gate_lab_enable_false_forces_mitigated(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    app.config["LAB_ENABLE"] = False

    # Trigger error must be sanitized
    response = submit_error(client, "divide_by_zero")
    assert response.status_code == 500
    assert "Sanitized generic error response returned" in response.get_data(as_text=True)

    # /debug-status must be 403 Forbidden
    debug_resp = client.get("/security-lab/security-misconfiguration/debug-status")
    assert debug_resp.status_code == 403


def test_gate_production_env_forces_mitigated(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    app.config["APP_ENV"] = "production"

    response = submit_error(client, "divide_by_zero")
    assert response.status_code == 500
    assert "Sanitized generic error response returned" in response.get_data(as_text=True)

    debug_resp = client.get("/security-lab/security-misconfiguration/debug-status")
    assert debug_resp.status_code == 403


def test_gate_non_loopback_remote_addr_forces_mitigated(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    # Disable outer loopback middleware abort to directly test the central safety gate
    app.config["ENFORCE_LOOPBACK"] = False

    response = submit_error(
        client,
        "divide_by_zero",
        environ_overrides={"REMOTE_ADDR": "198.51.100.2"},
    )
    assert response.status_code == 500
    assert "Sanitized generic error response returned" in response.get_data(as_text=True)

    debug_resp = client.get(
        "/security-lab/security-misconfiguration/debug-status",
        environ_overrides={"REMOTE_ADDR": "198.51.100.2"},
    )
    assert debug_resp.status_code == 403


# ---------------------------------------------------------------------------
# AUTHENTICATION & ACCESS BOUNDARY PRESERVATION TESTS
# ---------------------------------------------------------------------------


def test_debug_status_requires_authentication(client):
    """Confirm /debug-status is NOT publicly accessible and preserves lab auth boundary."""
    response = client.get("/security-lab/security-misconfiguration/debug-status")
    # Flask-Login redirects unauthenticated requests to /auth/login (HTTP 302)
    assert response.status_code in (302, 401)
    if response.status_code == 302:
        assert "/auth/login" in response.headers.get("Location", "")


def test_page_requires_authentication(client):
    """Confirm /security-misconfiguration page requires authentication."""
    response = client.get("/security-lab/security-misconfiguration")
    assert response.status_code in (302, 401)
    if response.status_code == 302:
        assert "/auth/login" in response.headers.get("Location", "")


# ---------------------------------------------------------------------------
# REGRESSION, ISOLATION & CSRF TESTS
# ---------------------------------------------------------------------------


def test_normal_application_error_handlers_unaffected(app, client):
    """Verify normal error handlers (e.g. 404) are completely unaffected by misconfig mode."""
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    response = client.get("/non-existent-route-404-test")
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "SecureHire-Synthetic-Lab-Daemon" not in response.headers.get("Server", "")
    assert "X-Debug-Mode" not in response.headers
    assert "ZeroDivisionError" not in body


def test_normal_routes_security_headers_unaffected(app, client):
    """Verify normal marketplace routes retain strict security headers."""
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    response = client.get("/gigs")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "SecureHire-Synthetic-Lab-Daemon" not in response.headers.get("Server", "")
    assert "X-Debug-Mode" not in response.headers


def test_csrf_protection_on_trigger_error(app, client):
    """Verify trigger-error endpoint rejects requests without CSRF token."""
    admin_id = make_user(app, "admin@example.test", "admin")
    login_as(client, "admin@example.test")

    # Post without CSRF token
    response = client.post(
        "/security-lab/security-misconfiguration/trigger-error",
        data={"error_type": "divide_by_zero"},
    )
    assert response.status_code == 400


def test_lab_run_logging(app, client):
    """Verify that lab runs are recorded in LabRun with bounded status summaries."""
    admin_id = make_user(app, "admin@example.test", "admin")
    set_misconfig_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    # Trigger error
    submit_error(client, "divide_by_zero")

    with app.app_context():
        runs = (
            LabRun.query.filter_by(vulnerability_key="security_misconfiguration")
            .order_by(LabRun.id.desc())
            .all()
        )
        assert len(runs) >= 1
        latest_run = runs[0]
        assert latest_run.result == "passed"
        assert latest_run.mode == "vulnerable"


def test_reset_route_redirects(app, client):
    """Verify reset endpoint clears scenario and redirects to lab page."""
    admin_id = make_user(app, "admin@example.test", "admin")
    login_as(client, "admin@example.test")

    response = submit_reset(client)
    assert response.status_code == 302
    assert "/security-lab/security-misconfiguration" in response.headers.get("Location", "")
