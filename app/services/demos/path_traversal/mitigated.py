"""Mitigated Path Traversal service with canonical resolution and containment check."""

from datetime import datetime, timezone
from pathlib import Path
import re

from . import MAX_FILE_READ_BYTES
from .fixtures import ensure_path_traversal_fixtures, get_public_dir


def process_mitigated_read(requested_path: str) -> tuple[bool, dict[str, object], int]:
    """Safely resolve and retrieve a document from the public repository.

    Enforces:
    1. Null-byte rejection.
    2. Drive-letter and root-relative path rejection.
    3. Path canonicalization via Path.resolve().
    4. Strict directory containment via is_relative_to(public_dir).
    5. Capped read length to prevent memory exhaustion.
    """
    ensure_path_traversal_fixtures()
    public_dir = get_public_dir()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    base_evidence: dict[str, object] = {
        "effective_mode": "mitigated",
        "requested_path": requested_path,
        "resolved_path": "None",
        "target_subdirectory": "public",
        "containment_verdict": "UNKNOWN",
        "file_content_preview": None,
        "expected_behavior": (
            "Canonicalizes the requested path using Path.resolve() and verifies "
            "containment inside the public documents directory via is_relative_to(). "
            "Rejects any traversal sequences (../, ..\\) that escape the designated folder."
        ),
        "observed_behavior": "",
        "mitigation_status": "PROTECTED - Canonical resolution & containment verified.",
        "timestamp": now_iso,
    }

    raw_path = requested_path.strip()
    if not raw_path:
        base_evidence["containment_verdict"] = "INVALID_PATH"
        base_evidence["observed_behavior"] = "Rejected: Document path cannot be empty."
        return False, base_evidence, 400

    if "\x00" in raw_path:
        base_evidence["containment_verdict"] = "INVALID_PATH"
        base_evidence["observed_behavior"] = (
            "Blocked: Embedded null byte (\\x00) detected in requested path."
        )
        return False, base_evidence, 400

    # Reject drive-letter specifications (e.g. C:\...) or leading root slashes
    if re.match(r"^[a-zA-Z]:", raw_path) or raw_path.startswith(("/", "\\")):
        base_evidence["containment_verdict"] = "TRAVERSAL_BLOCKED"
        base_evidence["observed_behavior"] = (
            "Blocked: Absolute path or drive-letter specification rejected. "
            "Paths must be relative to the public document repository."
        )
        return False, base_evidence, 400

    # Normalize backslashes to forward slashes for cross-platform processing
    normalized_rel = raw_path.replace("\\", "/")

    # Detect relative directory navigation sequences (.., ..., ...., etc.)
    try:
        path_parts = Path(normalized_rel).parts
    except Exception:
        path_parts = ()
    if any(re.match(r"^\.{2,}", part) for part in path_parts):
        base_evidence["resolved_path"] = "[BLOCKED - Traversal sequence detected]"
        base_evidence["containment_verdict"] = "TRAVERSAL_BLOCKED"
        base_evidence["observed_behavior"] = (
            f"Blocked: Traversal sequence '{raw_path}' detected in path component. "
            "Relative directory traversal is strictly forbidden."
        )
        return False, base_evidence, 400

    # Canonicalize target path
    try:
        target_path = (public_dir / normalized_rel).resolve()
    except Exception as exc:
        base_evidence["containment_verdict"] = "INVALID_PATH"
        base_evidence["observed_behavior"] = f"Rejected: Failed to resolve path ({exc})."
        return False, base_evidence, 400

    # Enforce directory containment: target must be inside public_dir
    if not target_path.is_relative_to(public_dir):
        base_evidence["resolved_path"] = "[BLOCKED - Escaped public directory]"
        base_evidence["containment_verdict"] = "TRAVERSAL_BLOCKED"
        base_evidence["observed_behavior"] = (
            f"Blocked: Traversal sequence '{raw_path}' attempted to escape the public directory. "
            f"Containment check is_relative_to('{public_dir.name}') rejected the request."
        )
        return False, base_evidence, 400

    # Check file existence and type
    if not target_path.exists() or not target_path.is_file():
        base_evidence["resolved_path"] = f"public/{target_path.name}"
        base_evidence["containment_verdict"] = "FILE_NOT_FOUND"
        base_evidence["observed_behavior"] = (
            f"File not found: '{target_path.name}' does not exist inside the public directory."
        )
        return False, base_evidence, 404

    # Safely read content with bounded length
    try:
        content = target_path.read_text(encoding="utf-8", errors="replace")[:MAX_FILE_READ_BYTES]
    except OSError as exc:
        base_evidence["containment_verdict"] = "READ_ERROR"
        base_evidence["observed_behavior"] = f"Error reading document: {exc}"
        return False, base_evidence, 500

    base_evidence["resolved_path"] = f"public/{target_path.name}"
    base_evidence["containment_verdict"] = "CONTAINED_IN_PUBLIC"
    base_evidence["file_content_preview"] = content
    base_evidence["observed_behavior"] = (
        f"Success: Document 'public/{target_path.name}' verified inside the public directory "
        "and retrieved securely."
    )
    return True, base_evidence, 200
