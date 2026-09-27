"""Tests for Milestone 9: Path Traversal demonstration and mitigations."""

from pathlib import Path
import shutil

import pytest

from app.extensions import db
from app.models import LabRun, SecurityMode
from app.services.demos.path_traversal import (
    DEFAULT_DOCUMENT,
    PRESET_MAP,
    SYNTHETIC_PUBLIC_FIXTURES,
    SYNTHETIC_RESTRICTED_FIXTURES,
)
from app.services.demos.path_traversal.fixtures import (
    ensure_path_traversal_fixtures,
    get_path_traversal_fixtures_root,
    get_public_dir,
    get_restricted_dir,
    reset_path_traversal_fixtures,
)
from conftest import csrf_token, login_as, make_user, post_form


TEST_USER_EMAIL = "freelancer@example.test"
ADMIN_USER_EMAIL = "admin@example.test"


@pytest.fixture(autouse=True)
def clean_path_traversal_fixtures(app):
    """Ensure path traversal fixtures are cleanly provisioned before and cleaned after tests."""
    with app.app_context():
        reset_path_traversal_fixtures()
    yield
    with app.app_context():
        root = get_path_traversal_fixtures_root()
        if root.exists():
            for item in root.iterdir():
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                elif item.is_file():
                    try:
                        item.unlink()
                    except OSError:
                        pass


def set_path_traversal_mode(app, mode: str):
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="path_traversal").one_or_none()
        if setting is None:
            db.session.add(SecurityMode(vulnerability_key="path_traversal", mode=mode))
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


def test_path_traversal_page_requires_authentication(client):
    response = client.get("/security-lab/path-traversal")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_path_traversal_page_renders_mitigated_by_default(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/path-traversal")
    assert response.status_code == 200
    assert b"Path Traversal" in response.data
    assert b"Effective mode: MITIGATED" in response.data
    assert b"Protection: PROTECTED" in response.data
    assert b"ATTACK FLOW" in response.data
    assert b"DOCUMENT VIEWER DEMONSTRATION" in response.data
    assert b"MITIGATION" in response.data
    assert b"Demonstration not implemented yet." not in response.data


def test_path_traversal_detail_dispatcher_renders(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/path_traversal")
    assert response.status_code == 200
    assert b"Path Traversal" in response.data
    assert b"Effective mode: MITIGATED" in response.data


# =====================================================================
# 2. Mitigated Mode Validation Tests
# =====================================================================


def test_mitigated_accepts_legitimate_public_file(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "freelancer_guidelines.txt"},
    )
    assert response.status_code == 200
    assert b"CONTAINED IN PUBLIC" in response.data
    assert b"Professional Communication" in response.data

    with app.app_context():
        last_run = LabRun.query.filter_by(vulnerability_key="path_traversal").order_by(LabRun.id.desc()).first()
        assert last_run is not None
        assert last_run.result == "passed"
        assert last_run.mode == "mitigated"


def test_mitigated_accepts_preset_legitimate(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "legitimate_public", "document_path": ""},
    )
    assert response.status_code == 200
    assert b"CONTAINED IN PUBLIC" in response.data
    assert b"freelancer_guidelines.txt" in response.data


def test_mitigated_blocks_forward_slash_traversal(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../restricted/synthetic_server_config.ini"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data
    assert b"Blocked: Traversal sequence" in response.data
    assert b"synthetic_server_configuration" not in response.data

    with app.app_context():
        last_run = LabRun.query.filter_by(vulnerability_key="path_traversal").order_by(LabRun.id.desc()).first()
        assert last_run is not None
        assert last_run.result == "blocked"


def test_mitigated_blocks_windows_backslash_traversal(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": r"..\restricted\synthetic_server_config.ini"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data
    assert b"synthetic_server_configuration" not in response.data


def test_mitigated_blocks_nested_traversal(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "....//restricted/synthetic_server_config.ini"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data
    assert b"synthetic_server_configuration" not in response.data


def test_mitigated_blocks_confidential_contract_traversal(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../restricted/confidential_contract.txt"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data
    assert b"CLASSIFICATION: RESTRICTED" not in response.data


def test_mitigated_blocks_absolute_drive_path(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": r"C:\Windows\win.ini"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data


def test_mitigated_blocks_leading_root_slash(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "/restricted/synthetic_server_config.ini"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data


def test_mitigated_blocks_null_byte_injection(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "freelancer_guidelines.txt\x00.ini"},
    )
    assert response.status_code == 400
    assert b"Embedded null byte" in response.data


def test_mitigated_handles_nonexistent_file(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "does_not_exist.txt"},
    )
    assert response.status_code == 404
    assert b"FILE_NOT_FOUND" in response.data


def test_mitigated_handles_empty_path(client, app):
    setup_auth(client, app)
    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "   "},
    )
    assert response.status_code == 400


# =====================================================================
# 3. Vulnerable Mode Traversal Tests
# =====================================================================


def test_vulnerable_mode_allows_traversal_to_restricted_fixture(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../restricted/synthetic_server_config.ini"},
    )
    assert response.status_code == 200
    assert b"ESCAPED TO RESTRICTED FIXTURE" in response.data
    assert b"[synthetic_server_configuration]" in response.data
    assert b"lab_secret_token = synthetic-lab-dummy-key" in response.data

    with app.app_context():
        last_run = LabRun.query.filter_by(vulnerability_key="path_traversal").order_by(LabRun.id.desc()).first()
        assert last_run is not None
        assert last_run.result == "passed"
        assert last_run.mode == "vulnerable"


def test_vulnerable_mode_allows_traversal_with_windows_backslash(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": r"..\restricted\synthetic_server_config.ini"},
    )
    assert response.status_code == 200
    assert b"ESCAPED TO RESTRICTED FIXTURE" in response.data
    assert b"synthetic_server_configuration" in response.data


def test_vulnerable_mode_allows_traversal_to_confidential_contract(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../restricted/confidential_contract.txt"},
    )
    assert response.status_code == 200
    assert b"ESCAPED TO RESTRICTED FIXTURE" in response.data
    assert b"CLASSIFICATION: RESTRICTED INTERNAL RECORD" in response.data


def test_vulnerable_mode_serves_legitimate_public_file(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "freelancer_guidelines.txt"},
    )
    assert response.status_code == 200
    assert b"CONTAINED IN PUBLIC" in response.data
    assert b"Professional Communication" in response.data


# =====================================================================
# 4. Hard Laboratory Safety Boundary Tests (Zero OS File Access)
# =====================================================================


def test_vulnerable_mode_blocks_host_os_escape_attempt(client, app):
    """Verify that even in vulnerable mode, escaping the lab root is blocked."""
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../../../../Windows/win.ini"},
    )
    assert response.status_code == 400
    assert b"OUT OF BOUNDS BLOCKED" in response.data
    assert b"Hard Laboratory Boundary" in response.data

    with app.app_context():
        last_run = LabRun.query.filter_by(vulnerability_key="path_traversal").order_by(LabRun.id.desc()).first()
        assert last_run is not None
        assert last_run.result == "blocked"


def test_vulnerable_mode_blocks_unix_os_escape_attempt(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../../../../../etc/passwd"},
    )
    assert response.status_code == 400
    assert b"OUT OF BOUNDS BLOCKED" in response.data


def test_vulnerable_mode_blocks_absolute_drive_path(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": r"C:\Windows\System32\drivers\etc\hosts"},
    )
    assert response.status_code == 400
    assert b"OUT OF BOUNDS BLOCKED" in response.data


# =====================================================================
# 5. Fail-Closed Safety Gate Tests
# =====================================================================


def test_vulnerable_mode_fails_closed_when_lab_enable_false(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = False

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../restricted/synthetic_server_config.ini"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data
    assert b"synthetic_server_configuration" not in response.data

    with app.app_context():
        last_run = LabRun.query.filter_by(vulnerability_key="path_traversal").order_by(LabRun.id.desc()).first()
        assert last_run is not None
        assert last_run.mode == "mitigated"


def test_vulnerable_mode_fails_closed_in_production_environment(client, app):
    setup_auth(client, app)
    set_path_traversal_mode(app, "vulnerable")
    app.config["LAB_ENABLE"] = True
    app.config["APP_ENV"] = "production"

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal",
        {"preset_case": "custom", "document_path": "../restricted/synthetic_server_config.ini"},
    )
    assert response.status_code == 400
    assert b"TRAVERSAL BLOCKED" in response.data


# =====================================================================
# 6. Reset & CSRF Protection Tests
# =====================================================================


def test_path_traversal_reset_endpoint(client, app):
    setup_auth(client, app)
    # Modify a fixture
    with app.app_context():
        public_file = get_public_dir() / "freelancer_guidelines.txt"
        public_file.write_text("Modified text for test", encoding="utf-8")
        assert public_file.read_text(encoding="utf-8") == "Modified text for test"

    response = post_form(
        client,
        "/security-lab/path-traversal",
        "/security-lab/path-traversal/reset",
        {},
    )
    assert response.status_code == 302
    assert "/security-lab/path-traversal" in response.headers["Location"]

    with app.app_context():
        public_file = get_public_dir() / "freelancer_guidelines.txt"
        assert "Professional Communication" in public_file.read_text(encoding="utf-8")


def test_path_traversal_submit_requires_csrf(client, app):
    setup_auth(client, app)
    response = client.post(
        "/security-lab/path-traversal",
        data={"preset_case": "custom", "document_path": "freelancer_guidelines.txt"},
    )
    assert response.status_code == 400


def test_path_traversal_reset_requires_csrf(client, app):
    setup_auth(client, app)
    response = client.post("/security-lab/path-traversal/reset", data={})
    assert response.status_code == 400


# =====================================================================
# 7. LabRun Bounded Schema & Isolation Verification
# =====================================================================


def test_lab_run_schema_has_no_payload_fields():
    column_names = {column.name for column in LabRun.__table__.columns}
    assert "payload" not in column_names
    assert "token" not in column_names
    assert "file_content" not in column_names
    assert "path" not in column_names


def test_synthetic_fixtures_isolated_to_lab_root(app):
    with app.app_context():
        root = get_path_traversal_fixtures_root()
        public = get_public_dir()
        restricted = get_restricted_dir()
        assert public.is_relative_to(root)
        assert restricted.is_relative_to(root)
        for pub_f in public.iterdir():
            assert pub_f.is_relative_to(root)
        for res_f in restricted.iterdir():
            assert res_f.is_relative_to(root)
