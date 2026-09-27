"""Storage management for the isolated file upload demonstration."""

from datetime import datetime, timezone
import os
from pathlib import Path

from flask import current_app


def get_lab_uploads_root() -> Path:
    """Return the designated root directory for Security Lab uploads."""
    config_folder = current_app.config.get("LAB_UPLOAD_FOLDER")
    if config_folder:
        root = Path(config_folder)
    else:
        root = Path(current_app.instance_path) / "lab_uploads"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def get_user_upload_dir(user_id: int) -> Path:
    """Return and create the isolated per-user upload directory."""
    root = get_lab_uploads_root()
    user_dir = (root / f"user_{user_id}").resolve()
    # Guard against escaping the lab uploads root
    if root not in user_dir.parents and user_dir != root:
        raise PermissionError("Directory traversal detected in user path.")
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


def sanitize_filename_base(filename: str) -> str:
    """Strip path components and directory traversal sequences."""
    base = os.path.basename(filename).strip()
    # Remove leading dots or null bytes
    base = base.replace("\x00", "").lstrip("./\\")
    if not base:
        raise ValueError("Filename cannot be empty.")
    return base


def save_lab_file(user_id: int, filename: str, content: bytes) -> tuple[Path, str]:
    """Store an uploaded file inside the user's isolated lab directory.

    To maintain bounded demonstration state, any previously stored file for this
    user is replaced.
    """
    user_dir = get_user_upload_dir(user_id)
    safe_name = sanitize_filename_base(filename)
    target_path = (user_dir / safe_name).resolve()

    if user_dir not in target_path.parents:
        raise PermissionError("Path traversal attempt blocked.")

    # Remove previous files to keep storage bounded per user
    for existing in user_dir.iterdir():
        if existing.is_file():
            try:
                existing.unlink()
            except OSError:
                pass

    with open(target_path, "wb") as f:
        f.write(content)

    return target_path, safe_name


def get_user_active_upload(user_id: int) -> dict[str, object] | None:
    """Retrieve metadata about the currently stored demonstration file for a user."""
    user_dir = get_user_upload_dir(user_id)
    if not user_dir.exists():
        return None

    files = [f for f in user_dir.iterdir() if f.is_file()]
    if not files:
        return None

    # Return the most recent file
    latest = max(files, key=lambda f: f.stat().st_mtime)
    stat = latest.stat()
    return {
        "filename": latest.name,
        "size_bytes": stat.st_size,
        "modified_iso": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(
            timespec="seconds"
        ),
        "path": str(latest),
    }


def delete_user_uploads(user_id: int) -> bool:
    """Delete all demonstration files for the specified user."""
    user_dir = get_user_upload_dir(user_id)
    if not user_dir.exists():
        return False

    deleted = False
    for existing in user_dir.iterdir():
        if existing.is_file():
            try:
                existing.unlink()
                deleted = True
            except OSError:
                pass
    return deleted


def get_file_for_download(user_id: int, filename: str) -> tuple[Path, str]:
    """Retrieve a file for safe attachment download, verifying boundary containment."""
    user_dir = get_user_upload_dir(user_id)
    safe_name = sanitize_filename_base(filename)
    target_path = (user_dir / safe_name).resolve()

    if user_dir not in target_path.parents:
        raise PermissionError("Path traversal attempt blocked.")
    if not target_path.exists() or not target_path.is_file():
        raise FileNotFoundError("Requested demonstration file does not exist.")

    return target_path, safe_name
