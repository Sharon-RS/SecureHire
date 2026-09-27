"""CSRF lab isolation, mode gating, and normal-route protection tests."""

from decimal import Decimal

import pytest

from app.extensions import db
from app.models import Gig, LabRun, Proposal, SecurityMode, User
from app.services.demos.csrf import (
    LAB_CSRF_BUYER_EMAIL,
    LAB_CSRF_COVER_LETTER,
    LAB_CSRF_FREELANCER_EMAIL,
    LAB_CSRF_GIG_CATEGORY,
    LAB_CSRF_GIG_TITLE,
)
from conftest import csrf_token, login_as, make_user


def make_csrf_fixture(app):
    buyer_id = make_user(app, LAB_CSRF_BUYER_EMAIL, "buyer", "Synthetic Buyer")
    freelancer_id = make_user(
        app, LAB_CSRF_FREELANCER_EMAIL, "freelancer", "Lab Freelancer B"
    )
    with app.app_context():
        buyer = db.session.get(User, buyer_id)
        freelancer = db.session.get(User, freelancer_id)
        gig = Gig(
            owner=buyer,
            title=LAB_CSRF_GIG_TITLE,
            description="A closed synthetic proposal reserved for the CSRF lab fixture.",
            category=LAB_CSRF_GIG_CATEGORY,
            budget=Decimal("900.00"),
            status="closed",
        )
        db.session.add(gig)
        db.session.flush()
        proposal = Proposal(
            gig=gig,
            freelancer=freelancer,
            cover_letter=LAB_CSRF_COVER_LETTER,
            proposed_price=Decimal("825.00"),
            timeline="Eleven synthetic workdays",
            status="pending",
        )
        db.session.add(proposal)
        db.session.commit()
        csrf_proposal_id = proposal.id

        ordinary_gig = Gig(
            owner=buyer,
            title="Ordinary synthetic marketplace gig",
            description="A normal marketplace record used to verify fixture isolation.",
            category="Design",
            budget=Decimal("500.00"),
            status="open",
        )
        db.session.add(ordinary_gig)
        db.session.flush()
        ordinary_proposal = Proposal(
            gig=ordinary_gig,
            freelancer=freelancer,
            cover_letter="An ordinary synthetic proposal that the CSRF lab must never change.",
            proposed_price=Decimal("450.00"),
            timeline="Five workdays",
            status="pending",
        )
        db.session.add(ordinary_proposal)
        db.session.commit()
        ordinary_proposal_id = ordinary_proposal.id
    return csrf_proposal_id, ordinary_proposal_id


def set_csrf_mode(app, mode="vulnerable"):
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="csrf").one_or_none()
        if setting is None:
            setting = SecurityMode(vulnerability_key="csrf", mode=mode)
            db.session.add(setting)
        else:
            setting.mode = mode
        db.session.commit()


def proposal_status(app, proposal_id):
    with app.app_context():
        return db.session.get(Proposal, proposal_id).status


def csrf_owner_client(app, client):
    make_csrf_fixture(app)
    login_as(client, LAB_CSRF_BUYER_EMAIL)


def test_csrf_page_explains_three_cases_and_never_prints_token(client, app):
    csrf_owner_client(app, client)

    response = client.get("/security-lab/csrf")
    assert response.status_code == 200
    for label in (
        b"Cross-Site Request Forgery (CSRF)",
        b"REQUEST",
        b"CSRF TOKEN",
        b"SERVER RESPONSE",
        b"STATE CHANGE",
        b"MITIGATION",
        b"Missing CSRF token",
        b"Invalid CSRF token",
        b"Valid CSRF token",
        b"Synthetic Buyer",
        b"Accept Freelancer B",
    ):
        assert label in response.data
    assert b"Demonstration not implemented yet." not in response.data


def test_normal_proposal_decision_rejects_missing_csrf_token(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post(
        f"/proposals/{csrf_proposal_id}/decision", data={"decision": "accepted"}
    )
    assert response.status_code == 400
    assert proposal_status(app, csrf_proposal_id) == "pending"


def test_normal_proposal_decision_rejects_invalid_csrf_token(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post(
        f"/proposals/{csrf_proposal_id}/decision",
        data={"decision": "accepted", "csrf_token": "invalid-normal-route-token"},
    )
    assert response.status_code == 400
    assert proposal_status(app, csrf_proposal_id) == "pending"


def test_normal_proposal_decision_accepts_a_valid_server_token(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    login_as(client, LAB_CSRF_BUYER_EMAIL)
    token = csrf_token(client, f"/proposals/{csrf_proposal_id}")

    response = client.post(
        f"/proposals/{csrf_proposal_id}/decision",
        data={"decision": "accepted", "csrf_token": token},
    )
    assert response.status_code == 302
    assert proposal_status(app, csrf_proposal_id) == "accepted"


def test_normal_proposal_decision_stays_csrf_protected_when_lab_mode_is_vulnerable(
    client, app
):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    for token in (None, "invalid-normal-route-token"):
        data = {"decision": "accepted"}
        if token is not None:
            data["csrf_token"] = token
        response = client.post(f"/proposals/{csrf_proposal_id}/decision", data=data)
        assert response.status_code == 400
        assert proposal_status(app, csrf_proposal_id) == "pending"

    token = csrf_token(client, f"/proposals/{csrf_proposal_id}")
    response = client.post(
        f"/proposals/{csrf_proposal_id}/decision",
        data={"decision": "accepted", "csrf_token": token},
    )
    assert response.status_code == 302
    assert proposal_status(app, csrf_proposal_id) == "accepted"


@pytest.mark.parametrize(
    ("token_case", "form_data"),
    [
        ("missing", {}),
        ("invalid", {"csrf_token": "invalid-securehire-lab-token"}),
    ],
)
def test_mitigated_lab_rejects_missing_and_invalid_tokens(client, app, token_case, form_data):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    set_csrf_mode(app, "mitigated")
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post("/security-lab/csrf/run", data=form_data)
    assert response.status_code == 400
    assert f"Token state</dt><dd class=\"col-sm-7\">{token_case.title()}".encode() in response.data
    assert b"State changed</dt><dd class=\"col-sm-7\">No" in response.data
    assert proposal_status(app, csrf_proposal_id) == "pending"


def test_mitigated_lab_accepts_valid_token_and_changes_only_fixture(client, app):
    csrf_proposal_id, ordinary_proposal_id = make_csrf_fixture(app)
    set_csrf_mode(app, "mitigated")
    login_as(client, LAB_CSRF_BUYER_EMAIL)
    token = csrf_token(client, "/security-lab/csrf")

    response = client.post("/security-lab/csrf/run", data={"csrf_token": token})
    assert response.status_code == 200
    assert b"MITIGATED" in response.data
    assert b"Valid" in response.data
    assert b"HTTP status</dt><dd class=\"col-sm-7\">200" in response.data
    assert b"State changed</dt><dd class=\"col-sm-7\">Yes" in response.data
    assert proposal_status(app, csrf_proposal_id) == "accepted"
    assert proposal_status(app, ordinary_proposal_id) == "pending"


def test_vulnerable_setting_is_blocked_when_lab_enable_is_false(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": False, "APP_ENV": "testing"})
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post("/security-lab/csrf/run", data={})
    assert response.status_code == 400
    assert b"MITIGATED" in response.data
    assert b"Token state</dt><dd class=\"col-sm-7\">Missing" in response.data
    assert proposal_status(app, csrf_proposal_id) == "pending"


def test_vulnerable_setting_is_blocked_outside_development_or_testing(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "production"})
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post("/security-lab/csrf/run", data={})
    assert response.status_code == 400
    assert b"MITIGATED" in response.data
    assert proposal_status(app, csrf_proposal_id) == "pending"


def test_vulnerable_setting_is_blocked_for_non_loopback_even_with_forwarded_local_header(
    client, app
):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post(
        "/security-lab/csrf/run",
        data={},
        headers={"X-Forwarded-For": "127.0.0.1"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert response.status_code == 403
    assert proposal_status(app, csrf_proposal_id) == "pending"


@pytest.mark.parametrize(
    ("token_case", "form_data"),
    [
        ("missing", {}),
        ("invalid", {"csrf_token": "invalid-securehire-lab-token"}),
    ],
)
def test_complete_gate_allows_only_the_isolated_vulnerable_lab_action(
    client, app, token_case, form_data
):
    csrf_proposal_id, ordinary_proposal_id = make_csrf_fixture(app)
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post("/security-lab/csrf/run", data=form_data)
    assert response.status_code == 200
    assert b"VULNERABLE" in response.data
    assert f"Token state</dt><dd class=\"col-sm-7\">{token_case.title()}".encode() in response.data
    assert b"State changed</dt><dd class=\"col-sm-7\">Yes" in response.data
    assert proposal_status(app, csrf_proposal_id) == "accepted"
    assert proposal_status(app, ordinary_proposal_id) == "pending"
    with app.app_context():
        run = LabRun.query.filter_by(vulnerability_key="csrf").one()
        assert run.mode == "vulnerable"
        assert run.result == "passed"


def test_vulnerable_lab_ignores_arbitrary_proposal_id_and_changes_only_fixed_fixture(
    client, app
):
    csrf_proposal_id, ordinary_proposal_id = make_csrf_fixture(app)
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, LAB_CSRF_BUYER_EMAIL)

    response = client.post(
        "/security-lab/csrf/run",
        data={"proposal_id": str(ordinary_proposal_id)},
    )
    assert response.status_code == 200
    assert proposal_status(app, csrf_proposal_id) == "accepted"
    assert proposal_status(app, ordinary_proposal_id) == "pending"


def test_non_owner_cannot_run_vulnerable_csrf_lab_action(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    make_user(app, "other-buyer@example.test", "buyer", "Other Buyer")
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, "other-buyer@example.test")

    response = client.post("/security-lab/csrf/run", data={})
    assert response.status_code == 403
    assert proposal_status(app, csrf_proposal_id) == "pending"


def test_security_lab_admin_controls_remain_csrf_protected_in_vulnerable_mode(client, app):
    make_user(app, "lab-admin@example.test", "admin", "Lab Admin")
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, "lab-admin@example.test")

    assert client.get("/security-lab").status_code == 200
    response = client.post("/security-lab/csrf/mode", data={"mode": "mitigated"})
    assert response.status_code == 400
    with app.app_context():
        assert SecurityMode.query.filter_by(vulnerability_key="csrf").one().mode == "vulnerable"


def test_mode_change_accepts_valid_csrf_and_cannot_be_selected_by_client_without_it(
    client, app
):
    make_user(app, "lab-admin@example.test", "admin", "Lab Admin")
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, "lab-admin@example.test")
    token = csrf_token(client, "/security-lab")

    response = client.post(
        "/security-lab/csrf/mode",
        data={"mode": "mitigated", "csrf_token": token},
    )
    assert response.status_code == 302
    with app.app_context():
        assert SecurityMode.query.filter_by(vulnerability_key="csrf").one().mode == "mitigated"


def test_fixture_reset_remains_csrf_protected_in_vulnerable_mode(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    login_as(client, LAB_CSRF_BUYER_EMAIL)
    run = client.post("/security-lab/csrf/run", data={})
    assert run.status_code == 200
    assert proposal_status(app, csrf_proposal_id) == "accepted"

    denied = client.post("/security-lab/csrf/reset", data={})
    assert denied.status_code == 400
    assert proposal_status(app, csrf_proposal_id) == "accepted"

    token = csrf_token(client, "/security-lab/csrf")
    reset = client.post("/security-lab/csrf/reset", data={"csrf_token": token})
    assert reset.status_code == 302
    assert proposal_status(app, csrf_proposal_id) == "pending"


def test_login_remains_csrf_protected_when_csrf_lab_mode_is_vulnerable(client, app):
    make_user(app, LAB_CSRF_BUYER_EMAIL, "buyer")
    set_csrf_mode(app, "vulnerable")
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})

    response = client.post(
        "/auth/login",
        data={"email": LAB_CSRF_BUYER_EMAIL, "password": "SecureHire-Test-Password!"},
    )
    assert response.status_code == 400


def test_lab_run_records_never_store_raw_token_values(client, app):
    csrf_proposal_id, _ = make_csrf_fixture(app)
    set_csrf_mode(app, "mitigated")
    login_as(client, LAB_CSRF_BUYER_EMAIL)
    raw_invalid_value = "unique-invalid-csrf-token-sentinel"

    response = client.post(
        "/security-lab/csrf/run", data={"csrf_token": raw_invalid_value}
    )
    assert response.status_code == 400
    assert raw_invalid_value.encode() not in response.data
    assert proposal_status(app, csrf_proposal_id) == "pending"
    with app.app_context():
        run = LabRun.query.filter_by(vulnerability_key="csrf").one()
        assert run.result == "passed"
        assert "token" not in {column.name for column in LabRun.__table__.columns}
