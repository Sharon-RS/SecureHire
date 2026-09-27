"""Mitigated file upload workflow enforcing defense-in-depth."""

from datetime import datetime, timezone

from . import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES
from .storage import save_lab_file
from .validation import (
    detect_mime_type,
    get_file_extension,
    sanitize_storage_filename,
    validate_extension,
    validate_magic_bytes,
)


def process_mitigated_upload(
    user_id: int, original_filename: str, content: bytes
) -> tuple[bool, dict[str, object], int]:
    """Execute the hardened upload pipeline with multi-layer verification.

    Returns:
        tuple of (success: bool, evidence: dict, http_status: int)
    """
    ext = get_file_extension(original_filename)
    detected_mime = detect_mime_type(content, original_filename)
    size_bytes = len(content)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # 1. Reject empty submissions
    if size_bytes == 0:
        evidence = {
            "effective_mode": "mitigated",
            "original_filename": original_filename,
            "stored_filename": None,
            "detected_mime": detected_mime,
            "file_size_bytes": size_bytes,
            "validation_verdict": "REJECTED: Empty file content",
            "expected_behavior": "Mitigated mode rejects zero-byte uploads.",
            "observed_behavior": "Server rejected the empty upload with HTTP 400.",
            "mitigation_status": "Empty file checks prevented zero-byte storage.",
            "is_stored": False,
            "timestamp": now_iso,
        }
        return False, evidence, 400

    # 2. Enforce file size limit
    if size_bytes > MAX_FILE_SIZE_BYTES:
        evidence = {
            "effective_mode": "mitigated",
            "original_filename": original_filename,
            "stored_filename": None,
            "detected_mime": detected_mime,
            "file_size_bytes": size_bytes,
            "validation_verdict": f"REJECTED: File size ({size_bytes} B) exceeds maximum allowed ({MAX_FILE_SIZE_BYTES} B)",
            "expected_behavior": "Mitigated mode enforces an upload size ceiling (512 KB) to prevent DoS.",
            "observed_behavior": f"Server rejected the oversized upload ({size_bytes} bytes) with HTTP 400.",
            "mitigation_status": "File size capping is active.",
            "is_stored": False,
            "timestamp": now_iso,
        }
        return False, evidence, 400

    # 3. Enforce extension allowlist
    if not validate_extension(original_filename):
        evidence = {
            "effective_mode": "mitigated",
            "original_filename": original_filename,
            "stored_filename": None,
            "detected_mime": detected_mime,
            "file_size_bytes": size_bytes,
            "validation_verdict": f"REJECTED: Disallowed extension '{ext or 'none'}'",
            "expected_behavior": f"Mitigated mode allows only approved extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}.",
            "observed_behavior": f"Server rejected extension '{ext}' with HTTP 400; dangerous file was not saved.",
            "mitigation_status": "Strict extension allowlisting blocked unapproved file type.",
            "is_stored": False,
            "timestamp": now_iso,
        }
        return False, evidence, 400

    # 4. Enforce magic bytes / file signature inspection
    is_magic_valid, signature_mime = validate_magic_bytes(content, ext)
    if not is_magic_valid:
        evidence = {
            "effective_mode": "mitigated",
            "original_filename": original_filename,
            "stored_filename": None,
            "detected_mime": signature_mime,
            "file_size_bytes": size_bytes,
            "validation_verdict": f"REJECTED: Content header mismatch for extension '{ext}'",
            "expected_behavior": "Mitigated mode verifies that file headers match the claimed extension.",
            "observed_behavior": f"Server detected MIME mismatch ({signature_mime} != {ext}) and returned HTTP 400.",
            "mitigation_status": "File signature inspection defeated extension disguise attempt.",
            "is_stored": False,
            "timestamp": now_iso,
        }
        return False, evidence, 400

    # 5. Sanitize storage filename with random UUID
    storage_name = sanitize_storage_filename(original_filename)

    # 6. Save in isolated non-executable directory
    save_lab_file(user_id, storage_name, content)

    evidence = {
        "effective_mode": "mitigated",
        "original_filename": original_filename,
        "stored_filename": storage_name,
        "detected_mime": signature_mime,
        "file_size_bytes": size_bytes,
        "validation_verdict": "ACCEPTED: Passed all security validations",
        "expected_behavior": "Mitigated mode accepts valid documents/images and renames them to random UUIDs.",
        "observed_behavior": f"The file was validated and stored safely as '{storage_name}' outside web root.",
        "mitigation_status": "Extension allowlist, signature check, size limit, and UUID naming all passed.",
        "is_stored": True,
        "timestamp": now_iso,
    }
    return True, evidence, 200
