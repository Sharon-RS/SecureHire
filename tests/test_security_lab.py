"""Security Lab framework safety, authorization, and audit tests."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.extensions import db
from app.models import LabRun, SecurityAuditLog, SecurityMode
from app.services import security_modes
from app.services.security_modes import (
    ALLOWED_LAB_RESULTS,
    AdministratorRequired,
    InvalidLabRunResult,
    InvalidSecurityMode,
    UnknownVulnerabilityKey,
    VULNERABILITIES,
    get_persisted_mode,
    record_lab_run,
    resolve_effective_mode,
    update_persisted_mode,
)
from conftest import csrf_token, login_as, make_user


def store_vulnerable_mode(app, key="sqli"):
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key=key).one_or_none()
        if setting is None:
            setting = SecurityMode(vulnerability_key=key, mode="vulnerable")
            db.session.add(setting)
        else:
            setting.mode = "vulnerable"
        db.session.commit()


def test_all_modules_default_to_mitigated_and_model_default_is_mitigated(app):
    assert len(VULNERABILITIES) == 10
    with app.app_context():
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            for module in VULNERABILITIES:
                assert resolve_effective_mode(module.key) == "mitigated"
        setting = SecurityMode(vulnerability_key="sqli")
        db.session.add(setting)
        db.session.flush()
        assert setting.mode == "mitigated"


def test_unknown_vulnerability_key_is_rejected(app):
    with app.app_context(), pytest.raises(UnknownVulnerabilityKey):
        resolve_effective_mode("not-a-real-module")


def test_invalid_mode_is_rejected_before_database_change(app):
    admin_id = make_user(app, "lab-admin@example.test", "admin")
    with app.app_context(), pytest.raises(InvalidSecurityMode):
        update_persisted_mode("sqli", "unsafe", admin_id)


def test_missing_persisted_setting_resolves_to_mitigated_when_gate_is_open(app):
    app.config["LAB_ENABLE"] = True
    with app.app_context():
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert resolve_effective_mode("sqli") == "mitigated"


def test_vulnerable_mode_is_blocked_when_lab_enable_is_false(app):
    store_vulnerable_mode(app)
    app.config["LAB_ENABLE"] = False
    with app.app_context():
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert resolve_effective_mode("sqli") == "mitigated"


def test_vulnerable_mode_is_blocked_in_production(app):
    store_vulnerable_mode(app)
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "production"})
    with app.app_context():
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert resolve_effective_mode("sqli") == "mitigated"


def test_vulnerable_mode_is_blocked_for_non_loopback_socket_peer(app):
    store_vulnerable_mode(app)
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    with app.app_context():
        with app.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "198.51.100.20"},
            headers={"Host": "localhost", "X-Forwarded-For": "127.0.0.1"},
        ):
            assert resolve_effective_mode("sqli") == "mitigated"


def test_vulnerable_mode_is_effective_only_when_every_gate_condition_is_met(app):
    store_vulnerable_mode(app)
    app.config.update({"LAB_ENABLE": True, "APP_ENV": "testing"})
    with app.app_context():
        with app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "::1"}, headers={"Host": "attacker.invalid"}
        ):
            assert resolve_effective_mode("sqli") == "vulnerable"


def test_non_admin_cannot_view_controls_or_change_mode(app):
    make_user(app, "buyer@example.test", "buyer")
    client = app.test_client()
    login_as(client, "buyer@example.test")

    assert client.get("/security-lab").status_code == 403
    token = csrf_token(client, "/dashboard")
    response = client.post(
        "/security-lab/sqli/mode",
        data={"csrf_token": token, "mode": "vulnerable"},
    )
    assert response.status_code == 403
    with app.app_context():
        assert SecurityMode.query.filter_by(vulnerability_key="sqli").one_or_none() is None


def test_admin_can_change_mode_and_create_audit_record_without_changing_other_modules(app):
    admin_id = make_user(app, "lab-admin@example.test", "admin")
    client = app.test_client()
    login_as(client, "lab-admin@example.test")
    token = csrf_token(client, "/security-lab")

    response = client.post(
        "/security-lab/sqli/mode",
        data={"csrf_token": token, "mode": "vulnerable"},
    )
    assert response.status_code == 302
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="sqli").one()
        audit = SecurityAuditLog.query.filter_by(vulnerability_key="sqli").one()
        assert setting.mode == "vulnerable"
        assert setting.updated_by == admin_id
        assert audit.previous_mode == "mitigated"
        assert audit.new_mode == "vulnerable"
        assert audit.changed_by == admin_id
        assert SecurityMode.query.filter_by(vulnerability_key="stored_xss").one_or_none() is None

    dashboard = client.get("/security-lab")
    assert dashboard.status_code == 200
    assert b"Effective mode" in dashboard.data
    assert b"MITIGATED" in dashboard.data
    for module in VULNERABILITIES:
        assert module.name.encode() in dashboard.data


def test_security_lab_mode_changes_require_csrf(app):
    make_user(app, "lab-admin@example.test", "admin")
    client = app.test_client()
    login_as(client, "lab-admin@example.test")
    response = client.post("/security-lab/sqli/mode", data={"mode": "vulnerable"})
    assert response.status_code == 400


def test_warning_banner_is_shown_only_when_vulnerable_mode_is_effective(app):
    app.config["LAB_ENABLE"] = True
    make_user(app, "lab-admin@example.test", "admin")
    store_vulnerable_mode(app)
    client = app.test_client()
    login_as(client, "lab-admin@example.test")

    response = client.get("/security-lab")
    assert response.status_code == 200
    assert b"EDUCATIONAL LAB MODE" in response.data
    assert b"VULNERABLE IMPLEMENTATION ENABLED" in response.data
    assert b"LOCALHOST ONLY" in response.data


def test_non_sqli_module_detail_remains_a_nonfunctional_placeholder(app):
    make_user(app, "freelancer@example.test", "freelancer")
    client = app.test_client()
    login_as(client, "freelancer@example.test")

    response = client.get("/security-lab/stored_xss")
    assert response.status_code == 200
    assert b"Demonstration not implemented yet." in response.data
    assert b"Planned mitigation" in response.data
    assert client.get("/security-lab/sqli").status_code == 200
    assert client.get("/security-lab/not-a-real-module").status_code == 404


def test_lab_run_records_contain_only_bounded_status_data(app):
    with app.app_context():
        record = record_lab_run("sqli", "not_implemented")
        assert record.mode == "mitigated"
        assert record.result in ALLOWED_LAB_RESULTS
        assert "payload" not in LabRun.__table__.columns
        assert "raw_payload" not in LabRun.__table__.columns
        with pytest.raises(InvalidLabRunResult):
            record_lab_run("sqli", "<script>synthetic payload</script>")



def test_invalid_lab_enable_value_fails_closed(app):
    store_vulnerable_mode(app)
    app.config.update({"LAB_ENABLE": "true", "APP_ENV": "testing"})
    with app.app_context():
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert resolve_effective_mode("sqli") == "mitigated"


def test_mode_endpoint_rejects_invalid_mode_values(app):
    make_user(app, "lab-admin@example.test", "admin")
    client = app.test_client()
    login_as(client, "lab-admin@example.test")
    token = csrf_token(client, "/security-lab")

    response = client.post(
        "/security-lab/sqli/mode",
        data={"csrf_token": token, "mode": "unsafe"},
    )
    assert response.status_code == 400
    with app.app_context():
        assert SecurityMode.query.filter_by(vulnerability_key="sqli").one_or_none() is None



def test_mode_service_also_rejects_non_admin_actor(app):
    buyer_id = make_user(app, "buyer@example.test", "buyer")
    with app.app_context(), pytest.raises(AdministratorRequired):
        update_persisted_mode("sqli", "vulnerable", buyer_id)



def test_invalid_persisted_mode_value_fails_closed(app, monkeypatch):
    query = Mock()
    query.filter_by.return_value.one_or_none.return_value = SimpleNamespace(mode="invalid")
    monkeypatch.setattr(security_modes, "SecurityMode", SimpleNamespace(query=query))
    with app.app_context():
        assert get_persisted_mode("sqli") == "mitigated"
