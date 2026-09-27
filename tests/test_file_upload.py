"""Tests for Milestone 8: Unrestricted File Upload demonstration and mitigations."""

import io
from pathlib import Path
import re
import shutil

import pytest

from app.extensions import db
from app.models import LabRun, SecurityMode, User
from app.services.demos.file_upload import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    MINIMAL_PNG_BYTES,
)
from app.services.demos.file_upload.storage import (
    get_lab_uploads_root,
    get_user_active_upload,
    get_user_upload_dir,
)
from conftest import csrf_token, login_as, make_user, post_form


TEST_USER_EMAIL = "freelancer@example.test"
ADMIN_USER_EMAIL = "admin@example.test"


@pytest.fixture(autouse=True)
def clean_lab_uploads(app):
    """Ensure the uploads folder is clean before and after every test."""
    def _cleanup():
        with app.app_context():
            root = get_lab_uploads_root()
            if root.exists():
                for item in root.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    elif item.is_file():
                        try:
                            item.unlink()
                        except OSError:
                            pass

    _cleanup()
    yield
    _cleanup()


def set_file_upload_mode(app, mode: str):
    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="file_upload").one_or_none()
        if setting is None:
            db.session.add(SecurityMode(vulnerability_key="file_upload", mode=mode))
        else:
            setting.mode = mode
        db.session.commit()


def setup_auth(client, app, role="freelancer", email=TEST_USER_EMAIL):
    user_id = make_user(app, email=email, role=role)
    login_as(client, email)
    return user_id


def upload_file(client, form_path, data):
    token = csrf_token(client, form_path)
    data["csrf_token"] = token
    return client.post(form_path, data=data, content_type="multipart/form-data")


# =====================================================================
# 1. Access Control & Page Display Tests
# =====================================================================


def test_file_upload_page_requires_authentication(client):
    response = client.get("/security-lab/file-upload")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_file_upload_page_renders_mitigated_by_default(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/file-upload")
    assert response.status_code == 200
    assert b"Unrestricted File Upload" in response.data
    assert b"Effective mode: MITIGATED" in response.data
    assert b"Protection: PROTECTED" in response.data
    assert b"ATTACK FLOW" in response.data
    assert b"UPLOAD DEMONSTRATION" in response.data
    assert b"MITIGATION" in response.data
    assert b"Demonstration not implemented yet." not in response.data


# =====================================================================
# 2. Mitigated Mode Validation Tests
# =====================================================================


def test_mitigated_mode_accepts_valid_text_file(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(b"Valid resume text content"), "resume.txt"),
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 200
    assert b"ACCEPTED: Passed all security validations" in response.data
    assert b"PASSED" in response.data

    with app.app_context():
        active = get_user_active_upload(user_id)
        assert active is not None
        assert active["filename"].endswith(".txt")
        # Filename should be sanitized UUID, not original 'resume.txt'
        assert active["filename"] != "resume.txt"
        assert len(active["filename"]) > 32


def test_mitigated_mode_accepts_valid_png_file(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(MINIMAL_PNG_BYTES), "diagram.png"),
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 200
    assert b"ACCEPTED: Passed all security validations" in response.data

    with app.app_context():
        active = get_user_active_upload(user_id)
        assert active is not None
        assert active["filename"].endswith(".png")


def test_mitigated_mode_rejects_disallowed_php_extension(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(b"<?php phpinfo(); ?>"), "shell.php"),
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 400
    assert b"REJECTED: Disallowed extension &#39;.php&#39;" in response.data or b"REJECTED: Disallowed extension '.php'" in response.data
    assert b"BLOCKED" in response.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


def test_mitigated_mode_rejects_disallowed_python_extension(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {
        "sample_case": "harmless_py",
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 400
    assert b"REJECTED: Disallowed extension" in response.data
    assert b"BLOCKED" in response.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


def test_mitigated_mode_rejects_magic_bytes_mismatch(client, app):
    """File claims to be .png but has PHP script content instead of PNG header."""
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(b"<?php echo 'disguised'; ?>"), "fake.png"),
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 400
    assert b"REJECTED: Content header mismatch" in response.data
    assert b"BLOCKED" in response.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


def test_mitigated_mode_rejects_disguised_sample_case(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {"sample_case": "disguised_ext"}
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 400
    assert b"REJECTED" in response.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


def test_mitigated_mode_rejects_oversized_file(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    oversized_content = b"A" * (MAX_FILE_SIZE_BYTES + 1024)
    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(oversized_content), "large.txt"),
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 400
    assert b"exceeds maximum allowed" in response.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


def test_mitigated_mode_rejects_empty_file(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(b""), "empty.txt"),
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 400
    assert b"Empty file content" in response.data


# =====================================================================
# 3. Vulnerable Mode & Gate Enforcement Tests
# =====================================================================


def test_vulnerable_mode_accepts_php_script_when_gate_is_open(client, app):
    user_id = setup_auth(client, app)
    app.config["LAB_ENABLE"] = True
    set_file_upload_mode(app, "vulnerable")

    data = {"sample_case": "harmless_php"}
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 200
    assert b"ACCEPTED (VULNERABLE)" in response.data
    assert b"harmless_poc.php" in response.data
    assert b"PASSED" in response.data

    with app.app_context():
        active = get_user_active_upload(user_id)
        assert active is not None
        assert active["filename"] == "harmless_poc.php"
        user_dir = get_user_upload_dir(user_id)
        stored_path = user_dir / "harmless_poc.php"
        assert stored_path.exists()
        # Verify file content was written as submitted
        assert b"SecureHire Security Lab" in stored_path.read_bytes()


def test_vulnerable_mode_fails_closed_when_lab_enable_is_false(client, app):
    user_id = setup_auth(client, app)
    app.config["LAB_ENABLE"] = False
    set_file_upload_mode(app, "vulnerable")

    # Gate is closed because LAB_ENABLE=False -> effective mode is mitigated
    data = {"sample_case": "harmless_php"}
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 400
    assert b"REJECTED: Disallowed extension" in response.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


def test_vulnerable_mode_fails_closed_on_non_loopback_remote_addr(client, app):
    user_id = setup_auth(client, app)
    app.config["LAB_ENABLE"] = True
    app.config["ENFORCE_LOOPBACK"] = False  # let app receive request but gate checks socket
    set_file_upload_mode(app, "vulnerable")

    token = csrf_token(client, "/security-lab/file-upload")
    response = client.post(
        "/security-lab/file-upload",
        data={"sample_case": "harmless_php", "csrf_token": token},
        environ_base={"REMOTE_ADDR": "198.51.100.24"},
    )
    # Gate fails closed to mitigated because remote_addr is not loopback
    assert response.status_code == 400
    assert b"REJECTED: Disallowed extension" in response.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


def test_vulnerable_mode_fails_closed_in_production(app):
    with app.app_context():
        app.config["LAB_ENABLE"] = True
        app.config["APP_ENV"] = "production"
        set_file_upload_mode(app, "vulnerable")

        from app.services.security_modes import resolve_effective_mode
        assert resolve_effective_mode("file_upload") == "mitigated"


# =====================================================================
# 4. Isolation, Zero Execution & Download Security Tests
# =====================================================================


def test_path_traversal_in_filename_is_stripped_to_basename(client, app):
    user_id = setup_auth(client, app)
    app.config["LAB_ENABLE"] = True
    set_file_upload_mode(app, "vulnerable")

    # Filename attempts to traverse up to the root
    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(b"malicious traversal attempt"), "../../../traversal_test.php"),
    }
    response = upload_file(client, "/security-lab/file-upload", data)
    assert response.status_code == 200

    with app.app_context():
        user_dir = get_user_upload_dir(user_id)
        # File must be stored strictly inside user_dir with basename only
        saved_file = user_dir / "traversal_test.php"
        assert saved_file.exists()
        # Verify it did not escape outside user_dir
        root = get_lab_uploads_root()
        assert not (root / "traversal_test.php").exists()


def test_safe_download_endpoint_headers(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(b"Document download test"), "document.txt"),
    }
    upload_file(client, "/security-lab/file-upload", data)

    with app.app_context():
        active = get_user_active_upload(user_id)
        filename = active["filename"]

    download_resp = client.get(f"/security-lab/file-upload/download/{filename}")
    assert download_resp.status_code == 200
    assert "attachment" in download_resp.headers.get("Content-Disposition", "")
    assert download_resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert download_resp.data == b"Document download test"


def test_download_blocks_cross_user_file_access(client, app):
    user_a_id = make_user(app, email="usera@example.test", role="freelancer")
    user_b_id = make_user(app, email="userb@example.test", role="freelancer")

    # User A uploads a file
    login_as(client, "usera@example.test")
    data = {
        "sample_case": "custom",
        "file": (io.BytesIO(b"User A secret file"), "secret_a.txt"),
    }
    upload_file(client, "/security-lab/file-upload", data)

    with app.app_context():
        active_a = get_user_active_upload(user_a_id)
        filename_a = active_a["filename"]

    # Switch session to User B (log out User A first)
    logout_token = csrf_token(client, "/dashboard")
    client.post("/auth/logout", data={"csrf_token": logout_token})
    login_as(client, "userb@example.test")
    # User B attempts to download User A's file
    cross_resp = client.get(f"/security-lab/file-upload/download/{filename_a}")
    assert cross_resp.status_code == 404


def test_download_rejects_path_traversal(client, app):
    setup_auth(client, app)
    response = client.get("/security-lab/file-upload/download/..%2F..%2F..%2Fetc%2Fpasswd")
    assert response.status_code in {400, 404}


# =====================================================================
# 5. Reset Action & CSRF Protection Tests
# =====================================================================


def test_reset_action_clears_stored_files_and_requires_csrf(client, app):
    user_id = setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    # Upload a file first
    data = {
        "sample_case": "benign_doc",
    }
    upload_file(client, "/security-lab/file-upload", data)

    with app.app_context():
        assert get_user_active_upload(user_id) is not None

    # Reset without CSRF token fails with HTTP 400
    bad_reset = client.post("/security-lab/file-upload/reset")
    assert bad_reset.status_code == 400
    with app.app_context():
        assert get_user_active_upload(user_id) is not None

    # Reset with valid CSRF token succeeds
    token = csrf_token(client, "/security-lab/file-upload")
    reset_resp = client.post("/security-lab/file-upload/reset", data={"csrf_token": token}, follow_redirects=True)
    assert reset_resp.status_code == 200
    assert b"Uploaded demonstration files cleared." in reset_resp.data

    with app.app_context():
        assert get_user_active_upload(user_id) is None


# =====================================================================
# 6. Audit & LabRun Bounded State Tests
# =====================================================================


def test_lab_run_stores_bounded_status_only_without_payload(client, app):
    setup_auth(client, app)
    set_file_upload_mode(app, "mitigated")

    data = {"sample_case": "benign_doc"}
    upload_file(client, "/security-lab/file-upload", data)

    with app.app_context():
        run = LabRun.query.filter_by(vulnerability_key="file_upload").order_by(LabRun.id.desc()).first()
        assert run is not None
        assert run.mode == "mitigated"
        assert run.result == "passed"
        # Verify schema has no payload or body column
        assert not hasattr(run, "payload")
        assert not hasattr(run, "body")
        assert not hasattr(run, "file_content")


def test_non_admin_cannot_change_file_upload_mode(client, app):
    setup_auth(client, app, role="freelancer")
    token = csrf_token(client, "/security-lab/file-upload")
    response = client.post(
        "/security-lab/file_upload/mode",
        data={"mode": "vulnerable", "csrf_token": token},
    )
    # Non-admin receives 403 Forbidden
    assert response.status_code == 403


def test_admin_can_change_file_upload_mode_with_csrf(client, app):
    setup_auth(client, app, role="admin", email=ADMIN_USER_EMAIL)
    token = csrf_token(client, "/security-lab")
    response = client.post(
        "/security-lab/file_upload/mode",
        data={"mode": "vulnerable", "csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200

    with app.app_context():
        setting = SecurityMode.query.filter_by(vulnerability_key="file_upload").one()
        assert setting.mode == "vulnerable"
