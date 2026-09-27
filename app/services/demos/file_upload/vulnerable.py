"""Vulnerable file upload workflow demonstrating missing validation risks."""

from datetime import datetime, timezone
import os

from .storage import sanitize_filename_base, save_lab_file
from .validation import detect_mime_type, get_file_extension


def process_vulnerable_upload(
    user_id: int, original_filename: str, content: bytes
) -> tuple[bool, dict[str, object], int]:
    """Execute the educational vulnerable upload pipeline.

    Demonstrates the risk of accepting arbitrary extensions without validation,
    while strictly enforcing isolation: files are never executed and remain
    confined to the isolated lab fixture directory.

    Returns:
        tuple of (success: bool, evidence: dict, http_status: int)
    """
    ext = get_file_extension(original_filename)
    detected_mime = detect_mime_type(content, original_filename)
    size_bytes = len(content)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if size_bytes == 0:
        evidence = {
            "effective_mode": "vulnerable",
            "original_filename": original_filename,
            "stored_filename": None,
            "detected_mime": detected_mime,
            "file_size_bytes": 0,
            "validation_verdict": "REJECTED: Empty file content",
            "expected_behavior": "Empty files are rejected even in vulnerable mode.",
            "observed_behavior": "Server rejected the empty upload with HTTP 400.",
            "mitigation_status": "Basic payload presence check prevented empty submission.",
            "is_stored": False,
            "timestamp": now_iso,
        }
        return False, evidence, 400

    # Retain the raw base filename and user-controlled extension
    # AGENTS.md Rule 5: Path traversal protection remains active (basename only)
    raw_basename = sanitize_filename_base(original_filename)

    # Intentionally bypass:
    # 1. Extension allowlisting (accepts .php, .py, .exe, .html, etc.)
    # 2. Magic bytes / file signature inspection
    # 3. Server-side UUID renaming (preserves original dangerous extension)
    save_lab_file(user_id, raw_basename, content)

    is_dangerous_ext = ext in {".php", ".py", ".sh", ".exe", ".html", ".htm", ".svg", ".js"}
    if is_dangerous_ext:
        risk_note = (
            f"In an unhardened production application, saving '{ext}' files in a web-accessible "
            "directory allows attackers to achieve Remote Code Execution (RCE) or Stored XSS."
        )
    else:
        risk_note = "The file was accepted without extension allowlisting or signature verification."

    evidence = {
        "effective_mode": "vulnerable",
        "original_filename": original_filename,
        "stored_filename": raw_basename,
        "detected_mime": detected_mime,
        "file_size_bytes": size_bytes,
        "validation_verdict": "ACCEPTED (VULNERABLE): Extension and MIME validation bypassed",
        "expected_behavior": "Vulnerable mode demonstrates unrestricted acceptance of arbitrary file types.",
        "observed_behavior": f"The server accepted '{raw_basename}' with unverified type '{detected_mime}'. {risk_note}",
        "mitigation_status": "Upload validation intentionally bypassed for demonstration. (Zero execution enforced).",
        "is_stored": True,
        "timestamp": now_iso,
    }
    return True, evidence, 200
