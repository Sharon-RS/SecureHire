"""Stored XSS isolation, mitigation, gate, and marketplace review tests."""

from markupsafe import escape

from app.extensions import db
from app.models import Gig, LabRun, Proposal, Review, SecurityMode, StoredXssDemoEntry
from app.services.demos.stored_xss import APPROVED_STORED_XSS_PAYLOAD
from conftest import csrf_token, login_as, make_user

PAYLOAD = APPROVED_STORED_XSS_PAYLOAD


def create_accepted_interaction(app, suffix="one"):
    buyer_id = make_user(app, f"buyer-{suffix}@example.test", "buyer", f"Buyer {suffix}")
    freelancer_id = make_user(
        app, f"freelancer-{suffix}@example.test", "freelancer", f"Freelancer {suffix}"
    )
    with app.app_context():
        gig = Gig(
            owner_id=buyer_id,
            title=f"Synthetic project {suffix}",
            description="A synthetic marketplace project description for review tests.",
            category="Testing",
            budget=500,
            status="open",
        )
        db.session.add(gig)
        db.session.flush()
        proposal = Proposal(
            gig_id=gig.id,
            freelancer_id=freelancer_id,
            cover_letter="A synthetic proposal for an accepted interaction.",
            proposed_price=400,
            timeline="Two weeks",
            status="accepted",
        )
        db.session.add(proposal)
        db.session.commit()
        return buyer_id, freelancer_id, gig.id, proposal.id


def set_stored_xss_mode(app, mode="vulnerable"):
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="stored_xss").one_or_none()
        if setting is None:
            db.session.add(SecurityMode(vulnerability_key="stored_xss", mode=mode))
        else:
            setting.mode = mode
        db.session.commit()


def store_lab_value(app, user_id):
    with app.app_context():
        db.session.add(StoredXssDemoEntry(user_id=user_id, payload=PAYLOAD))
        db.session.commit()


def submit_lab_value(client, query_string=None, extra_data=None):
    data = {"csrf_token": csrf_token(client, "/security-lab/stored-xss"), "payload": PAYLOAD}
    if extra_data:
        data.update(extra_data)
    return client.post(
        "/security-lab/stored-xss" + (query_string or ""),
        data=data,
        follow_redirects=True,
    )


def test_normal_review_is_authorized_server_derived_and_autoescaped(app):
    buyer_id, freelancer_id, gig_id, proposal_id = create_accepted_interaction(app)
    client = app.test_client()
    login_as(client, "freelancer-one@example.test")
    token = csrf_token(client, f"/proposals/{proposal_id}/review")
    response = client.post(
        f"/proposals/{proposal_id}/review",
        data={"csrf_token": token, "rating": "5", "body": PAYLOAD},
        follow_redirects=True,
    )

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert str(escape(PAYLOAD)) in text
    assert PAYLOAD not in text
    assert "Marketplace reviews" in text
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
    with app.app_context():
        review = Review.query.one()
        assert review.reviewer_id == freelancer_id
        assert review.reviewee_id == buyer_id
        assert review.proposal_id == proposal_id
        assert review.rating == 5
        assert review.body == PAYLOAD
        assert db.session.get(Gig, gig_id) is not None


def test_marketplace_review_remains_safe_when_stored_xss_mode_is_vulnerable(app):
    buyer_id, freelancer_id, gig_id, proposal_id = create_accepted_interaction(app, "safe-market")
    app.config["LAB_ENABLE"] = True
    set_stored_xss_mode(app)
    store_lab_value(app, freelancer_id)
    client = app.test_client()
    login_as(client, "freelancer-safe-market@example.test")

    token = csrf_token(client, f"/proposals/{proposal_id}/review")
    response = client.post(
        f"/proposals/{proposal_id}/review",
        data={"csrf_token": token, "rating": "4", "body": PAYLOAD},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert str(escape(PAYLOAD)) in response.get_data(as_text=True)
    assert PAYLOAD not in response.get_data(as_text=True)
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
    assert client.get(f"/gigs/{gig_id}").status_code == 200
    with app.app_context():
        assert Review.query.one().reviewee_id == buyer_id


def test_only_accepted_interaction_participants_can_review(app):
    buyer_id, freelancer_id, _gig_id, proposal_id = create_accepted_interaction(app, "authz")
    make_user(app, "outsider@example.test", "freelancer")
    client = app.test_client()
    login_as(client, "outsider@example.test")
    response = client.get(f"/proposals/{proposal_id}/review")
    assert response.status_code == 404

    client = app.test_client()
    login_as(client, "buyer-authz@example.test")
    token = csrf_token(client, f"/proposals/{proposal_id}/review")
    response = client.post(
        f"/proposals/{proposal_id}/review",
        data={"csrf_token": token, "rating": "5", "body": "A valid-length synthetic review."},
    )
    assert response.status_code == 302
    with app.app_context():
        review = Review.query.one()
        assert review.reviewer_id == buyer_id
        assert review.reviewee_id == freelancer_id


def test_lab_value_is_per_user_and_only_approved_input_is_accepted(app):
    make_user(app, "xss-one@example.test", "freelancer")
    make_user(app, "xss-two@example.test", "freelancer")
    app.config["LAB_ENABLE"] = True
    set_stored_xss_mode(app)
    client = app.test_client()
    login_as(client, "xss-one@example.test")
    response = submit_lab_value(client, extra_data={"payload": "<script>different()</script>"})
    assert response.status_code == 400
    with app.app_context():
        assert StoredXssDemoEntry.query.count() == 0
        assert LabRun.query.count() == 0

    response = submit_lab_value(client)
    assert response.status_code == 200
    assert b"VULNERABLE IMPLEMENTATION ENABLED" in response.data
    assert PAYLOAD.encode() in response.data
    client_two = app.test_client()
    login_as(client_two, "xss-two@example.test")
    second_response = client_two.get("/security-lab/stored_xss")
    assert second_response.status_code == 200
    assert PAYLOAD.encode() not in second_response.data
    with app.app_context():
        assert StoredXssDemoEntry.query.count() == 1
        assert LabRun.query.count() == 1
        assert "payload" not in LabRun.__table__.columns
        assert PAYLOAD not in repr(LabRun.query.all())


def test_mitigated_mode_escapes_the_same_stored_value_and_keeps_default_csp(app):
    user_id = make_user(app, "xss-mitigated@example.test", "freelancer")
    app.config["LAB_ENABLE"] = True
    set_stored_xss_mode(app, "mitigated")
    store_lab_value(app, user_id)
    client = app.test_client()
    login_as(client, "xss-mitigated@example.test")

    response = client.get("/security-lab/stored-xss")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert str(escape(PAYLOAD)) in text
    assert PAYLOAD not in text
    assert "Effective mode: MITIGATED" in text
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_vulnerable_mode_runs_only_when_lab_flag_is_enabled(app):
    user_id = make_user(app, "xss-gated@example.test", "freelancer")
    set_stored_xss_mode(app)
    store_lab_value(app, user_id)
    app.config["LAB_ENABLE"] = False
    client = app.test_client()
    login_as(client, "xss-gated@example.test")

    response = client.get("/security-lab/stored-xss")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Effective mode: MITIGATED" in text
    assert str(escape(PAYLOAD)) in text
    assert PAYLOAD not in text
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_vulnerable_mode_is_blocked_in_production(app):
    user_id = make_user(app, "xss-production@example.test", "freelancer")
    set_stored_xss_mode(app)
    store_lab_value(app, user_id)
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "production"})
    client = app.test_client()
    login_as(client, "xss-production@example.test")

    response = client.get("/security-lab/stored-xss")
    assert response.status_code == 200
    assert str(escape(PAYLOAD)) in response.get_data(as_text=True)
    assert PAYLOAD not in response.get_data(as_text=True)
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_vulnerable_mode_is_blocked_for_non_loopback_peer(app):
    user_id = make_user(app, "xss-remote@example.test", "freelancer")
    app.config["LAB_ENABLE"] = True
    set_stored_xss_mode(app)
    store_lab_value(app, user_id)
    client = app.test_client()
    login_as(client, "xss-remote@example.test")

    response = client.get(
        "/security-lab/stored_xss",
        environ_base={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert response.status_code == 403
    assert PAYLOAD.encode() not in response.data


def test_vulnerable_mode_renders_raw_value_and_scoped_csp_when_gate_is_open(app):
    user_id = make_user(app, "xss-vulnerable@example.test", "freelancer")
    app.config["LAB_ENABLE"] = True
    set_stored_xss_mode(app)
    store_lab_value(app, user_id)
    client = app.test_client()
    login_as(client, "xss-vulnerable@example.test")

    response = client.get("/security-lab/stored-xss")
    assert response.status_code == 200
    assert PAYLOAD.encode() in response.data
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self' 'unsafe-inline'" in csp
    assert "default-src 'self'" in csp
    assert b"VULNERABLE IMPLEMENTATION ENABLED" in response.data


def test_unapproved_database_value_stays_escaped_even_in_vulnerable_mode(app):
    user_id = make_user(app, "xss-corrupt@example.test", "freelancer")
    app.config["LAB_ENABLE"] = True
    set_stored_xss_mode(app)
    with app.app_context():
        db.session.add(
            StoredXssDemoEntry(
                user_id=user_id,
                payload='<script>alert("unapproved")</script>',
            )
        )
        db.session.commit()
    client = app.test_client()
    login_as(client, "xss-corrupt@example.test")

    response = client.get("/security-lab/stored-xss")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert '&lt;script&gt;alert(&#34;unapproved&#34;)&lt;/script&gt;' in text
    assert '<script>alert("unapproved")</script>' not in text
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]


def test_client_parameters_cannot_turn_on_vulnerable_mode(app):
    user_id = make_user(app, "xss-client-mode@example.test", "freelancer")
    app.config["LAB_ENABLE"] = True
    store_lab_value(app, user_id)
    client = app.test_client()
    login_as(client, "xss-client-mode@example.test")

    response = client.get("/security-lab/stored_xss?mode=vulnerable")
    assert response.status_code == 200
    assert str(escape(PAYLOAD)) in response.get_data(as_text=True)
    assert PAYLOAD not in response.get_data(as_text=True)
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]

    response = submit_lab_value(
        client,
        query_string="?mode=vulnerable",
        extra_data={"mode": "vulnerable"},
    )
    assert response.status_code == 200
    assert PAYLOAD.encode() not in response.data
    assert str(escape(PAYLOAD)).encode() in response.data
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="stored_xss").one()
        assert setting.mode == "mitigated"
        assert LabRun.query.one().mode == "mitigated"
