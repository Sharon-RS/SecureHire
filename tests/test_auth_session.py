"""Authentication & Session Security lab tests.

Verifies:
- Mitigated mode: session rotation upon login, pre-auth token invalidation,
  server-side session invalidation on logout, secure cookie attributes (HttpOnly, SameSite=Lax).
- Vulnerable mode: session fixation (omitting rotation), SIMULATED ACCOUNT TAKEOVER
  confirmation via pre-auth token, stale session reuse after flawed logout,
  insecure demo cookie attributes (omitted HttpOnly, omitted SameSite).
- Fail-closed central safety gate enforcement.
- Strict isolation & regression protection: Real Flask session cookie ('session')
  permanently retains HttpOnly and SameSite=Lax even when auth_session is Vulnerable.
- Real Flask-Login and normal application routes are never authenticated or altered
  by synthetic lab tokens.
- CSRF protection on lab action forms and bounded LabRun records.
"""

import pytest

from app.extensions import db
from app.models import LabRun, SecurityMode, User
from app.services.demos.auth_session import (
    AUTH_SESSION_COOKIE_NAME,
    INITIAL_PRE_AUTH_TOKEN,
    LABEL_ACCESS_DENIED,
    LABEL_SESSION_REVOKED,
    LABEL_SIMULATED_TAKEOVER,
    LABEL_STALE_SESSION_REPLAY,
)
from app.services.demos.auth_session.store import (
    get_active_session,
    get_pre_auth_token,
    get_store_snapshot,
    reset_auth_session_store,
)
from app.services.security_modes import update_persisted_mode
from conftest import csrf_token, login_as, make_user, post_form


@pytest.fixture(autouse=True)
def reset_store_before_each_test():
    """Ensure every test begins with a pristine synthetic session store."""
    reset_auth_session_store()
    yield
    reset_auth_session_store()


def set_auth_session_mode(app, mode: str, admin_id: int):
    with app.app_context():
        update_persisted_mode("auth_session", mode, admin_id)


# ---------------------------------------------------------------------------
# MITIGATED MODE TESTS
# ---------------------------------------------------------------------------


def test_mitigated_login_rotates_session_and_sets_secure_cookies(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    # Step 1: Simulate Consultant Login in Mitigated mode
    response = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    assert response.status_code == 200
    assert b"SESSION ROTATION APPLIED" in response.data

    snapshot = get_store_snapshot()
    active = snapshot.get("active_session")
    assert active is not None
    # Session must be rotated: new token != pre-auth token
    assert active["token"] != snapshot["pre_auth_token"]
    assert active["is_authenticated"] is True

    # Check synthetic demo cookie on response
    demo_cookies = [
        val for val in response.headers.getlist("Set-Cookie")
        if val.startswith(f"{AUTH_SESSION_COOKIE_NAME}=")
    ]
    assert len(demo_cookies) > 0
    demo_cookie = demo_cookies[0]
    assert "HttpOnly" in demo_cookie
    assert "SameSite=Lax" in demo_cookie


def test_mitigated_mode_rejects_attacker_pre_auth_token(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    # First simulate login so a rotated session is created
    post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )

    # Attacker attempts to use the pre-authentication kiosk token
    pre_auth_token = get_pre_auth_token()
    response = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/inspect-token",
        {"token": pre_auth_token},
    )
    # Mitigated mode must reject access to the pre-auth token
    assert response.status_code == 401
    assert LABEL_ACCESS_DENIED.encode() in response.data
    assert b"SIMULATED ACCOUNT TAKEOVER" not in response.data


def test_mitigated_mode_logout_invalidates_session_server_side(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    # Login -> get rotated token
    post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    snapshot = get_store_snapshot()
    active_token = snapshot["active_session"]["token"]

    # Logout
    logout_resp = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-logout",
        {},
    )
    assert logout_resp.status_code == 200
    assert b"SERVER-SIDE SESSION INVALIDATION APPLIED" in logout_resp.data

    # Replay discarded token
    replay_resp = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/replay-token",
        {"token": active_token},
    )
    assert replay_resp.status_code == 401
    assert LABEL_SESSION_REVOKED.encode() in replay_resp.data


# ---------------------------------------------------------------------------
# VULNERABLE MODE TESTS
# ---------------------------------------------------------------------------


def test_vulnerable_mode_omits_rotation_and_confirms_simulated_takeover(app, client):
    app.config["LAB_ENABLE"] = True
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    pre_auth_token = get_pre_auth_token()

    # Step 1: Simulate Consultant Login in Vulnerable mode
    response = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    assert response.status_code == 200
    assert b"SESSION FIXATION VULNERABILITY (NO ROTATION)" in response.data

    snapshot = get_store_snapshot()
    active = snapshot.get("active_session")
    assert active is not None
    # Vulnerable mode reuses the pre-auth token without rotation!
    assert active["token"] == pre_auth_token

    # Step 2: Attacker inspects their pre-auth kiosk token
    inspect_resp = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/inspect-token",
        {"token": pre_auth_token},
    )
    assert inspect_resp.status_code == 200
    assert LABEL_SIMULATED_TAKEOVER.encode() in inspect_resp.data
    assert b"SIMULATED ACCOUNT TAKEOVER DETECTED" in inspect_resp.data


def test_vulnerable_mode_demo_cookie_omits_security_flags(app, client):
    app.config["LAB_ENABLE"] = True
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    response = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    demo_cookies = [
        val for val in response.headers.getlist("Set-Cookie")
        if val.startswith(f"{AUTH_SESSION_COOKIE_NAME}=")
    ]
    assert len(demo_cookies) > 0
    demo_cookie = demo_cookies[0]
    # Vulnerable demo cookie omits HttpOnly
    assert "HttpOnly" not in demo_cookie


def test_vulnerable_mode_flawed_logout_allows_stale_token_replay(app, client):
    app.config["LAB_ENABLE"] = True
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    # Login
    post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    pre_auth_token = get_pre_auth_token()

    # Logout (flawed: does not invalidate on server)
    logout_resp = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-logout",
        {},
    )
    assert logout_resp.status_code == 200

    # Replay token
    replay_resp = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/replay-token",
        {"token": pre_auth_token},
    )
    assert replay_resp.status_code == 200
    assert LABEL_STALE_SESSION_REPLAY.encode() in replay_resp.data or LABEL_SIMULATED_TAKEOVER.encode() in replay_resp.data


# ---------------------------------------------------------------------------
# FAIL-CLOSED SAFETY GATE TESTS
# ---------------------------------------------------------------------------


def test_vulnerable_mode_fails_closed_when_lab_enable_is_false(app, client):
    app.config["LAB_ENABLE"] = False
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    response = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    assert response.status_code == 200
    # Must fail closed to Mitigated: session rotation applied
    assert b"SESSION ROTATION APPLIED" in response.data
    snapshot = get_store_snapshot()
    assert snapshot["active_session"]["token"] != snapshot["pre_auth_token"]


def test_vulnerable_mode_fails_closed_when_non_loopback(app, client):
    app.config["LAB_ENABLE"] = True
    app.config["ENFORCE_LOOPBACK"] = False  # let request reach application
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    token = csrf_token(client, "/security-lab/auth-session")
    response = client.post(
        "/security-lab/auth-session/simulate-login",
        data={"csrf_token": token},
        environ_base={"REMOTE_ADDR": "198.51.100.25"},
    )
    assert response.status_code == 200
    # Central gate detects non-loopback -> fails closed to Mitigated
    assert b"SESSION ROTATION APPLIED" in response.data


# ---------------------------------------------------------------------------
# EXPLICIT REGRESSION PROTECTION & ISOLATION TESTS (MANDATORY CONSTRAINT)
# ---------------------------------------------------------------------------


def test_real_flask_session_cookie_retains_httponly_and_samesite_when_auth_session_is_vulnerable(
    app, client
):
    """Proves that the real application session cookie ('session') is NEVER weakened,
    even when the auth_session security lab is in Vulnerable mode."""
    app.config["LAB_ENABLE"] = True
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "vulnerable", admin_id)

    # Perform normal application login
    response = login_as(client, "admin@example.test")
    assert response.status_code == 302

    # Find the real Flask session cookie
    real_session_cookie = next(
        val for val in response.headers.getlist("Set-Cookie") if val.startswith("session=")
    )
    # The real session cookie MUST retain full security flags
    assert "HttpOnly" in real_session_cookie
    assert "SameSite=Lax" in real_session_cookie


def test_synthetic_lab_token_never_authenticates_flask_login_or_marketplace_routes(
    app, client
):
    """Proves that synthetic lab tokens exist solely in the lab and cannot authenticate
    normal SecureHire application routes, Flask-Login, or current_user."""
    app.config["LAB_ENABLE"] = True
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "vulnerable", admin_id)
    login_as(client, "admin@example.test")

    # Execute lab login to activate synthetic session
    post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    snapshot = get_store_snapshot()
    active_token = snapshot["active_session"]["token"]

    # Now create an unauthenticated client that only presents the synthetic cookie
    isolated_client = app.test_client()
    isolated_client.set_cookie(AUTH_SESSION_COOKIE_NAME, active_token)

    # Attempt to access protected marketplace and user profile routes
    resp_dashboard = isolated_client.get("/dashboard")
    assert resp_dashboard.status_code == 302
    assert "/auth/login" in resp_dashboard.headers["Location"]

    resp_profile = isolated_client.get("/auth/profile")
    assert resp_profile.status_code == 302
    assert "/auth/login" in resp_profile.headers["Location"]

    resp_admin = isolated_client.get("/security-lab")
    assert resp_admin.status_code == 302
    assert "/auth/login" in resp_admin.headers["Location"]


def test_auth_session_actions_require_valid_csrf(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    login_as(client, "admin@example.test")

    # Missing CSRF token must return 400
    resp_login = client.post("/security-lab/auth-session/simulate-login", data={})
    assert resp_login.status_code == 400

    resp_inspect = client.post("/security-lab/auth-session/inspect-token", data={})
    assert resp_inspect.status_code == 400

    resp_logout = client.post("/security-lab/auth-session/simulate-logout", data={})
    assert resp_logout.status_code == 400

    resp_reset = client.post("/security-lab/auth-session/reset", data={})
    assert resp_reset.status_code == 400


def test_auth_session_records_bounded_lab_run(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )

    with app.app_context():
        runs = (
            LabRun.query.filter_by(vulnerability_key="auth_session")
            .order_by(LabRun.id.desc())
            .all()
        )
        assert len(runs) > 0
        latest = runs[0]
        assert latest.result in {"passed", "blocked"}
        assert latest.mode == "mitigated"


def test_auth_session_reset_restores_clean_initial_state(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    login_as(client, "admin@example.test")

    # Simulate login
    post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/simulate-login",
        {},
    )
    assert get_store_snapshot()["active_session"] is not None

    # Reset
    reset_resp = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/reset",
        {},
    )
    assert reset_resp.status_code == 302
    snapshot = get_store_snapshot()
    assert snapshot["active_session"] is None
    assert snapshot["pre_auth_token"] == INITIAL_PRE_AUTH_TOKEN


def test_unauthenticated_user_cannot_access_auth_session_lab(client):
    response = client.get("/security-lab/auth-session")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_non_admin_cannot_change_auth_session_mode(app, client):
    make_user(app, "buyer@example.test", "buyer")
    login_as(client, "buyer@example.test")

    token = csrf_token(client, "/dashboard")
    response = client.post(
        "/security-lab/auth_session/mode",
        data={"csrf_token": token, "mode": "vulnerable"},
    )
    assert response.status_code == 403
    with app.app_context():
        from app.services.security_modes import get_module_state
        state = get_module_state("auth_session")
        assert state["stored_mode"] == "mitigated"


def test_module_detail_routes_to_auth_session_page(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    login_as(client, "admin@example.test")

    response = client.get("/security-lab/auth_session")
    assert response.status_code == 200
    assert b"Authentication &amp; Session Security" in response.data or b"Authentication & Session Security" in response.data


def test_replay_corrupted_token_returns_401(app, client):
    admin_id = make_user(app, "admin@example.test", "admin")
    set_auth_session_mode(app, "mitigated", admin_id)
    login_as(client, "admin@example.test")

    response = post_form(
        client,
        "/security-lab/auth-session",
        "/security-lab/auth-session/replay-token",
        {"token": "totally-corrupted-or-fabricated-token-999"},
    )
    assert response.status_code == 401
    assert b"UNAUTHENTICATED SESSION" in response.data


def test_normal_logout_retains_csrf_and_clears_session(app, client):
    user_id = make_user(app, "freelancer@example.test", "freelancer")
    login_as(client, "freelancer@example.test")
    assert client.get("/dashboard").status_code == 200

    token = csrf_token(client, "/dashboard")
    logout_resp = client.post("/auth/logout", data={"csrf_token": token})
    assert logout_resp.status_code == 302
    assert logout_resp.headers["Location"].endswith("/")
    assert client.get("/dashboard").status_code == 302

