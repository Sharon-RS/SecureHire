"""Vulnerable Path Traversal service with hard lab boundary enforcement."""

from datetime import datetime, timezone
from pathlib import Path
import re

from . import MAX_FILE_READ_BYTES
from .fixtures import (
    ensure_path_traversal_fixtures,
    get_path_traversal_fixtures_root,
    get_public_dir,
    get_restricted_dir,
)


def process_vulnerable_read(requested_path: str) -> tuple[bool, dict[str, object], int]:
    """Demonstrate path traversal while strictly preserving host system safety.

    Educational Vulnerability:
    - Omission of the containment check against public_dir.
    - Resolves user-supplied traversal sequences (../, ..\\), allowing access
      to sibling synthetic fixtures in restricted/.

    Strict Safety Boundary:
    - Never accesses arbitrary OS files.
    - Confined strictly to the lab fixtures root (fixtures_root).
    - If a traversal payload attempts to escape fixtures_root (e.g. targeting
      C:\\Windows or /etc/), the hard laboratory boundary rejects it.
    """
    ensure_path_traversal_fixtures()
    fixtures_root = get_path_traversal_fixtures_root()
    public_dir = get_public_dir()
    restricted_dir = get_restricted_dir()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    base_evidence: dict[str, object] = {
        "effective_mode": "vulnerable",
        "requested_path": requested_path,
        "resolved_path": "None",
        "target_subdirectory": "public",
        "containment_verdict": "UNKNOWN",
        "file_content_preview": None,
        "expected_behavior": (
            "In an unhardened application, omitting path containment validation "
            "allows traversal sequences (../ or ..\\) to escape the intended directory "
            "and expose restricted server files."
        ),
        "observed_behavior": "",
        "mitigation_status": "VULNERABLE - Directory containment check intentionally omitted.",
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
            "Blocked: Embedded null byte (\\x00) detected."
        )
        return False, base_evidence, 400

    # Naive join omitting containment check, resolving traversal sequences
    # Convert backslashes for cross-platform resolution
    normalized_rel = raw_path.replace("\\", "/")
    # Educational simulation of naive filter: collapses redundant dots (....// -> ..//)
    collapsed = re.sub(r"\.{2,}", "..", normalized_rel)

    # Check for Windows absolute drive path (e.g. C:\...) or leading root slash
    # If the user passed an absolute path, Path(public_dir / raw) on Windows would switch drive!
    # Under the hard lab boundary, arbitrary drives/system roots are blocked.
    if collapsed.startswith("/") or (len(collapsed) >= 2 and collapsed[1] == ":"):
        target_path = Path(collapsed).resolve()
    else:
        target_path = (public_dir / collapsed).resolve()

    # =========================================================================
    # HARD LABORATORY SAFETY BOUNDARY (AGENTS.md Rule 6)
    # Even in vulnerable mode, the application MUST NOT access host OS files
    # =========================================================================
    if not target_path.is_relative_to(fixtures_root):
        base_evidence["resolved_path"] = "[BLOCKED - Escaped lab fixture root]"
        base_evidence["target_subdirectory"] = "out_of_bounds"
        base_evidence["containment_verdict"] = "OUT_OF_BOUNDS_BLOCKED"
        base_evidence["observed_behavior"] = (
            f"Blocked by Hard Laboratory Boundary: The payload '{raw_path}' attempted to escape "
            "the designated security lab fixture root. Access to host operating system files "
            "is strictly forbidden by AGENTS.md safety rules."
        )
        return False, base_evidence, 400

    # Determine whether the target resolved inside public/ or traversed into restricted/
    rel_to_root = target_path.relative_to(fixtures_root).as_posix()
    base_evidence["resolved_path"] = rel_to_root

    if target_path.is_relative_to(restricted_dir):
        base_evidence["target_subdirectory"] = "restricted"
        base_evidence["containment_verdict"] = "ESCAPED_TO_RESTRICTED"
    elif target_path.is_relative_to(public_dir):
        base_evidence["target_subdirectory"] = "public"
        base_evidence["containment_verdict"] = "CONTAINED_IN_PUBLIC"
    else:
        base_evidence["target_subdirectory"] = "other_lab_fixture"
        base_evidence["containment_verdict"] = "LAB_FIXTURE_ACCESSED"

    # Check file existence and type
    if not target_path.exists() or not target_path.is_file():
        base_evidence["containment_verdict"] = "FILE_NOT_FOUND"
        base_evidence["observed_behavior"] = (
            f"File not found: Target path '{rel_to_root}' does not exist inside the lab fixtures."
        )
        return False, base_evidence, 404

    # Read content from bounded synthetic fixture
    try:
        content = target_path.read_text(encoding="utf-8", errors="replace")[:MAX_FILE_READ_BYTES]
    except OSError as exc:
        base_evidence["containment_verdict"] = "READ_ERROR"
        base_evidence["observed_behavior"] = f"Error reading fixture: {exc}"
        return False, base_evidence, 500

    base_evidence["file_content_preview"] = content

    if base_evidence["containment_verdict"] == "ESCAPED_TO_RESTRICTED":
        base_evidence["observed_behavior"] = (
            f"Vulnerability Demonstrated: Traversal sequence successfully escaped the public "
            f"directory and accessed restricted internal fixture '{rel_to_root}'. "
            "In an unhardened environment, this allows reading arbitrary server files."
        )
    else:
        base_evidence["observed_behavior"] = (
            f"Document '{rel_to_root}' retrieved from the public directory."
        )

    return True, base_evidence, 200
