"""SQL injection demonstration behavior and isolation tests."""

from app.extensions import db
from app.models import Gig, LabGigFixture, LabRun, SecurityMode
from app.services.demos.sqli import SAFE_SQLI_PAYLOAD
from conftest import csrf_token, login_as, make_user, post_form


def seed_lab_fixtures(app):
    with app.app_context():
        db.session.add_all(
            [
                LabGigFixture(
                    title="Python",
                    category="Development",
                    description="A synthetic local fixture for a small Python automation task.",
                ),
                LabGigFixture(
                    title="Automate weekly reports",
                    category="Python",
                    description="A synthetic local fixture for a report-generation script.",
                ),
                LabGigFixture(
                    title="Brand icon refresh",
                    category="Design",
                    description="A synthetic local fixture for a simple visual identity update.",
                ),
            ]
        )
        db.session.commit()


def store_vulnerable_mode(app):
    with app.app_context():
        db.session.add(SecurityMode(vulnerability_key="sqli", mode="vulnerable"))
        db.session.commit()


def authenticated_client(app):
    make_user(app, "sqli-student@example.test", "freelancer")
    client = app.test_client()
    login_as(client, "sqli-student@example.test")
    return client


def run_search(client, term, **extra_fields):
    return post_form(
        client,
        "/security-lab/sqli",
        "/security-lab/sqli",
        {"search_term": term, **extra_fields},
    )


def test_mitigated_python_search_returns_only_matching_synthetic_lab_gigs(app):
    seed_lab_fixtures(app)
    client = authenticated_client(app)

    response = run_search(client, "Python")

    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert b"Automate weekly reports" in response.data
    assert b"<th scope=\"row\">Python</th>" in response.data
    assert b"Brand icon refresh" not in response.data
    assert b"2 of 3 synthetic fixtures" in response.data


def test_mitigated_mode_treats_the_approved_sqli_input_as_literal(app):
    seed_lab_fixtures(app)
    client = authenticated_client(app)

    response = run_search(client, SAFE_SQLI_PAYLOAD)

    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert b"0 of 3 synthetic fixtures" in response.data
    assert b"The approved SQLi string is a bound literal" in response.data
    assert b"&#39; OR &#39;1&#39;=&#39;1" in response.data
    assert b"SELECT id" not in response.data
    with app.app_context():
        assert LabRun.query.filter_by(vulnerability_key="sqli", mode="mitigated").one().result == "passed"


def test_vulnerable_mode_matches_all_and_only_synthetic_fixtures_when_gate_is_open(app):
    seed_lab_fixtures(app)
    store_vulnerable_mode(app)
    app.config["LAB_ENABLE"] = True
    client = authenticated_client(app)

    response = run_search(client, SAFE_SQLI_PAYLOAD)

    assert response.status_code == 200
    assert b"Effective mode: VULNERABLE" in response.data
    assert b"3 of 3 synthetic fixtures" in response.data
    assert b"Python" in response.data
    assert b"Automate weekly reports" in response.data
    assert b"Brand icon refresh" in response.data
    assert b"unsafe OR expression broadens the search" in response.data
    with app.app_context():
        run = LabRun.query.filter_by(vulnerability_key="sqli").one()
        assert run.mode == "vulnerable"
        assert run.result == "passed"


def test_lab_search_is_read_only_except_for_bounded_payload_free_run_status(app):
    seed_lab_fixtures(app)
    store_vulnerable_mode(app)
    app.config["LAB_ENABLE"] = True
    client = authenticated_client(app)

    with app.app_context():
        fixture_rows_before = [
            (row.id, row.title, row.category, row.description)
            for row in LabGigFixture.query.order_by(LabGigFixture.id).all()
        ]
        marketplace_count_before = Gig.query.count()

    response = run_search(client, SAFE_SQLI_PAYLOAD)

    assert response.status_code == 200
    with app.app_context():
        fixture_rows_after = [
            (row.id, row.title, row.category, row.description)
            for row in LabGigFixture.query.order_by(LabGigFixture.id).all()
        ]
        assert fixture_rows_after == fixture_rows_before
        assert Gig.query.count() == marketplace_count_before
        assert LabRun.query.count() == 1
        assert "payload" not in LabRun.__table__.columns
        assert "raw_payload" not in LabRun.__table__.columns
        run = LabRun.query.one()
        assert SAFE_SQLI_PAYLOAD not in {
            str(getattr(run, column.name)) for column in LabRun.__table__.columns
        }


def test_vulnerable_setting_is_mitigated_when_explicit_lab_flag_is_off(app):
    seed_lab_fixtures(app)
    store_vulnerable_mode(app)
    app.config["LAB_ENABLE"] = False
    client = authenticated_client(app)

    response = run_search(client, SAFE_SQLI_PAYLOAD)

    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert b"0 of 3 synthetic fixtures" in response.data
    with app.app_context():
        assert LabRun.query.one().mode == "mitigated"


def test_vulnerable_setting_is_mitigated_when_app_environment_is_production(app):
    seed_lab_fixtures(app)
    store_vulnerable_mode(app)
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "production"})
    client = authenticated_client(app)

    response = run_search(client, SAFE_SQLI_PAYLOAD)

    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert b"0 of 3 synthetic fixtures" in response.data


def test_non_loopback_peer_cannot_run_the_vulnerable_demo(app):
    seed_lab_fixtures(app)
    store_vulnerable_mode(app)
    app.config["LAB_ENABLE"] = True
    client = authenticated_client(app)
    token = csrf_token(client, "/security-lab/sqli")

    response = client.post(
        "/security-lab/sqli",
        data={"csrf_token": token, "search_term": SAFE_SQLI_PAYLOAD},
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    )

    assert response.status_code == 403
    with app.app_context():
        assert LabRun.query.count() == 0


def test_client_cannot_select_vulnerable_mode_with_a_form_field(app):
    seed_lab_fixtures(app)
    client = authenticated_client(app)

    response = run_search(client, SAFE_SQLI_PAYLOAD, mode="vulnerable")

    assert response.status_code == 200
    assert b"Effective mode: MITIGATED" in response.data
    assert b"0 of 3 synthetic fixtures" in response.data
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="sqli").one()
        assert setting.mode == "mitigated"


def test_unapproved_sql_syntax_is_rejected_before_any_demo_query(app):
    seed_lab_fixtures(app)
    client = authenticated_client(app)

    response = run_search(client, "' OR '1'='1'--")

    assert response.status_code == 400
    with app.app_context():
        assert LabRun.query.count() == 0


def test_security_lab_search_keeps_csrf_protection_active(app):
    seed_lab_fixtures(app)
    client = authenticated_client(app)

    response = client.post(
        "/security-lab/sqli",
        data={"search_term": SAFE_SQLI_PAYLOAD},
    )

    assert response.status_code == 400
    with app.app_context():
        assert LabRun.query.count() == 0


def test_sqli_demo_does_not_change_normal_marketplace_search(app):
    seed_lab_fixtures(app)
    owner_id = make_user(app, "marketplace-owner@example.test", "buyer")
    with app.app_context():
        db.session.add(
            Gig(
                owner_id=owner_id,
                title="Unrelated synthetic marketplace gig",
                description="A standard marketplace record.",
                category="Design",
                budget="50.00",
                status="open",
            )
        )
        db.session.commit()
    client = authenticated_client(app)

    response = client.get("/gigs", query_string={"q": SAFE_SQLI_PAYLOAD})

    assert response.status_code == 200
    assert b"Unrelated synthetic marketplace gig" not in response.data
    with app.app_context():
        assert LabRun.query.count() == 0
