"""IDOR/BOLA demonstration, isolation, gate, and marketplace authorization tests."""

from decimal import Decimal

import pytest

from app.extensions import db
from app.models import Gig, LabRun, Proposal, SecurityAuditLog, SecurityMode
from app.services.demos.idor_bola import (
    LAB_FREELANCER_A_EMAIL,
    LAB_FREELANCER_B_EMAIL,
    LAB_SCENARIO_CATEGORY,
    LAB_SCENARIO_TITLE,
)
from conftest import csrf_token, login_as, make_user, post_form


A_COVER_LETTER = "Synthetic proposal A for the controlled IDOR/BOLA test fixture."
B_COVER_LETTER = (
    "Synthetic proposal B contains fixture-only planning details for the controlled lab."
)


def make_idor_scenario(app):
    buyer_id = make_user(app, "buyer@example.test", "buyer")
    freelancer_a_id = make_user(app, LAB_FREELANCER_A_EMAIL, "freelancer")
    freelancer_b_id = make_user(app, LAB_FREELANCER_B_EMAIL, "freelancer")
    with app.app_context():
        gig = Gig(
            owner_id=buyer_id,
            title=LAB_SCENARIO_TITLE,
            description="Closed synthetic fixture used only by the IDOR/BOLA Security Lab.",
            category=LAB_SCENARIO_CATEGORY,
            budget=Decimal("1000.00"),
            status="closed",
        )
        db.session.add(gig)
        db.session.flush()
        proposal_a = Proposal(
            gig_id=gig.id,
            freelancer_id=freelancer_a_id,
            cover_letter=A_COVER_LETTER,
            proposed_price=Decimal("725.00"),
            timeline="Ten synthetic workdays",
            status="pending",
        )
        proposal_b = Proposal(
            gig_id=gig.id,
            freelancer_id=freelancer_b_id,
            cover_letter=B_COVER_LETTER,
            proposed_price=Decimal("810.00"),
            timeline="Twelve synthetic workdays",
            status="pending",
        )
        db.session.add_all([proposal_a, proposal_b])
        db.session.commit()
        return {
            "buyer_id": buyer_id,
            "freelancer_a_id": freelancer_a_id,
            "freelancer_b_id": freelancer_b_id,
            "proposal_a_id": proposal_a.id,
            "proposal_b_id": proposal_b.id,
        }


def set_idor_mode(app, mode="mitigated", lab_enable=True, app_env="testing"):
    app.config.update({"LAB_ENABLE": lab_enable, "APP_ENV": app_env})
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="idor_bola").one_or_none()
        if setting is None:
            setting = SecurityMode(vulnerability_key="idor_bola", mode=mode)
            db.session.add(setting)
        else:
            setting.mode = mode
        db.session.commit()


def submit_target(client, proposal_id, extra=None, action="/security-lab/idor"):
    data = {"target_proposal_id": str(proposal_id)}
    if extra:
        data.update(extra)
    return post_form(client, "/security-lab/idor", action, data)


def test_idor_page_requires_authentication_and_does_not_create_fixtures(app):
    client = app.test_client()
    response = client.get("/security-lab/idor")
    assert response.status_code == 302

    make_user(app, LAB_FREELANCER_A_EMAIL, "freelancer")
    login_as(client, LAB_FREELANCER_A_EMAIL)
    response = client.get("/security-lab/idor")
    assert response.status_code == 200
    assert b"Synthetic proposal fixtures are not ready" in response.data
    with app.app_context():
        assert Gig.query.count() == 0
        assert Proposal.query.count() == 0


def test_vulnerable_mode_allows_only_the_bounded_synthetic_cross_user_read(app):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "vulnerable", lab_enable=True)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)

    response = submit_target(client, scenario["proposal_b_id"])
    assert response.status_code == 200
    assert b"Effective mode</dt><dd class=\"col-sm-7\">VULNERABLE" in response.data
    assert b"Authorization decision</dt><dd class=\"col-sm-7 fw-bold\">ALLOWED" in response.data
    assert b"Freelancer B" in response.data
    assert B_COVER_LETTER.encode() in response.data


def test_mitigated_mode_denies_cross_user_without_returning_proposal_contents(app):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "mitigated", lab_enable=True)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)

    response = submit_target(client, scenario["proposal_b_id"])
    assert response.status_code == 403
    assert b"Authorization decision</dt><dd class=\"col-sm-7 fw-bold\">DENIED" in response.data
    assert b"No proposal contents were returned" in response.data
    assert B_COVER_LETTER.encode() not in response.data


def test_mitigated_mode_allows_requesters_to_read_their_own_proposal(app):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "mitigated", lab_enable=True)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)

    response = submit_target(client, scenario["proposal_a_id"])
    assert response.status_code == 200
    assert b"Authorization decision</dt><dd class=\"col-sm-7 fw-bold\">ALLOWED" in response.data
    assert A_COVER_LETTER.encode() in response.data


@pytest.mark.parametrize(
    ("lab_enable", "app_env"),
    [(False, "testing"), (None, "testing"), ("true", "testing"), (True, "production")],
)
def test_vulnerable_setting_fails_closed_when_lab_gate_is_disabled_invalid_or_production(
    app, lab_enable, app_env
):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "vulnerable", lab_enable=lab_enable, app_env=app_env)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)

    response = submit_target(client, scenario["proposal_b_id"])
    assert response.status_code == 403
    assert b"Effective mode</dt><dd class=\"col-sm-7\">MITIGATED" in response.data
    assert B_COVER_LETTER.encode() not in response.data


def test_missing_persisted_mode_and_default_lab_flag_resolve_to_mitigated(app):
    scenario = make_idor_scenario(app)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)
    with app.app_context():
        assert SecurityMode.query.filter_by(vulnerability_key="idor_bola").one_or_none() is None

    response = submit_target(client, scenario["proposal_b_id"])
    assert response.status_code == 403
    assert b'Effective mode</dt><dd class="col-sm-7">MITIGATED' in response.data
    assert B_COVER_LETTER.encode() not in response.data
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="idor_bola").one()
        assert setting.mode == "mitigated"


def test_non_loopback_socket_peer_cannot_reach_vulnerable_demo_even_with_local_headers(app):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "vulnerable", lab_enable=True)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)
    token = csrf_token(client, "/security-lab/idor")

    response = client.post(
        "/security-lab/idor",
        data={"csrf_token": token, "target_proposal_id": str(scenario["proposal_b_id"])},
        environ_base={"REMOTE_ADDR": "198.51.100.23"},
        headers={"Host": "localhost", "X-Forwarded-For": "127.0.0.1"},
    )
    assert response.status_code == 403
    assert B_COVER_LETTER.encode() not in response.data
    with app.app_context():
        assert LabRun.query.filter_by(vulnerability_key="idor_bola").count() == 0


def test_client_supplied_mode_and_requester_ids_do_not_control_authorization(app):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "mitigated", lab_enable=True)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)

    denied = submit_target(
        client,
        scenario["proposal_b_id"],
        extra={"requester_id": str(scenario["freelancer_b_id"]), "mode": "vulnerable"},
    )
    assert denied.status_code == 403
    assert B_COVER_LETTER.encode() not in denied.data

    set_idor_mode(app, "vulnerable", lab_enable=True)
    attempted_override = submit_target(
        client,
        scenario["proposal_b_id"],
        extra={"requester_id": str(scenario["freelancer_b_id"]), "mode": "mitigated"},
        action="/security-lab/idor?mode=mitigated",
    )
    assert attempted_override.status_code == 200
    assert b"Effective mode</dt><dd class=\"col-sm-7\">VULNERABLE" in attempted_override.data
    assert B_COVER_LETTER.encode() in attempted_override.data


def test_demo_is_read_only_and_records_only_bounded_run_status(app):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "vulnerable", lab_enable=True)
    with app.app_context():
        before = [
            (p.id, p.gig_id, p.freelancer_id, p.cover_letter, p.proposed_price, p.timeline, p.status)
            for p in Proposal.query.order_by(Proposal.id).all()
        ]
        gigs_before = [
            (g.id, g.title, g.status, g.owner_id)
            for g in Gig.query.order_by(Gig.id).all()
        ]
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)

    response = submit_target(client, scenario["proposal_b_id"])
    assert response.status_code == 200
    with app.app_context():
        after = [
            (p.id, p.gig_id, p.freelancer_id, p.cover_letter, p.proposed_price, p.timeline, p.status)
            for p in Proposal.query.order_by(Proposal.id).all()
        ]
        gigs_after = [
            (g.id, g.title, g.status, g.owner_id)
            for g in Gig.query.order_by(Gig.id).all()
        ]
        run = LabRun.query.filter_by(vulnerability_key="idor_bola").one()
        assert after == before
        assert gigs_after == gigs_before
        assert run.mode == "vulnerable"
        assert run.result == "passed"
        assert "payload" not in LabRun.__table__.columns
        assert "requester_id" not in LabRun.__table__.columns


def test_normal_marketplace_authorization_stays_secure_while_lab_is_vulnerable(app):
    scenario = make_idor_scenario(app)
    set_idor_mode(app, "vulnerable", lab_enable=True)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)

    assert client.get(f"/proposals/{scenario['proposal_a_id']}").status_code == 200
    normal_cross_user = client.get(f"/proposals/{scenario['proposal_b_id']}")
    assert normal_cross_user.status_code == 404
    assert B_COVER_LETTER.encode() not in normal_cross_user.data

    lab_cross_user = submit_target(client, scenario["proposal_b_id"])
    assert lab_cross_user.status_code == 200
    assert B_COVER_LETTER.encode() in lab_cross_user.data


def test_demo_rejects_ids_outside_its_fixture_and_requires_csrf(app):
    scenario = make_idor_scenario(app)
    outsider_id = make_user(app, "unrelated@example.test", "freelancer")
    with app.app_context():
        other_gig = Gig(
            owner_id=scenario["buyer_id"],
            title="Unrelated synthetic gig",
            description="Not an IDOR fixture.",
            category="Design",
            budget=Decimal("500.00"),
            status="closed",
        )
        db.session.add(other_gig)
        db.session.flush()
        outsider_proposal = Proposal(
            gig_id=other_gig.id,
            freelancer_id=outsider_id,
            cover_letter="This unrelated proposal must never be returned by the lab.",
            proposed_price=Decimal("450.00"),
            timeline="One week",
            status="pending",
        )
        db.session.add(outsider_proposal)
        db.session.commit()
        outsider_proposal_id = outsider_proposal.id

    set_idor_mode(app, "vulnerable", lab_enable=True)
    client = app.test_client()
    login_as(client, LAB_FREELANCER_A_EMAIL)
    csrf = csrf_token(client, "/security-lab/idor")
    invalid = client.post(
        "/security-lab/idor",
        data={"csrf_token": csrf, "target_proposal_id": str(outsider_proposal_id)},
    )
    assert invalid.status_code == 400
    assert b"This unrelated proposal must never be returned" not in invalid.data

    missing_csrf = client.post(
        "/security-lab/idor",
        data={"target_proposal_id": str(scenario["proposal_b_id"])},
    )
    assert missing_csrf.status_code == 400
    assert B_COVER_LETTER.encode() not in missing_csrf.data


def test_security_lab_admin_can_change_idor_mode_server_side(app):
    admin_id = make_user(app, "idor-admin@example.test", "admin")
    client = app.test_client()
    login_as(client, "idor-admin@example.test")
    token = csrf_token(client, "/security-lab")

    response = client.post(
        "/security-lab/idor_bola/mode",
        data={"csrf_token": token, "mode": "vulnerable"},
    )
    assert response.status_code == 302
    with app.app_context():
        mode = SecurityMode.query.filter_by(vulnerability_key="idor_bola").one()
        audit = SecurityAuditLog.query.filter_by(vulnerability_key="idor_bola").one()
        assert mode.mode == "vulnerable"
        assert mode.updated_by == admin_id
        assert audit.new_mode == "vulnerable"
    dashboard = client.get("/security-lab")
    assert b"/security-lab/idor" in dashboard.data
    assert b"Open demonstration" in dashboard.data
