"""Dedicated synthetic fixture provisioning and management for Path Traversal."""

from pathlib import Path
import shutil

from flask import current_app

from . import SYNTHETIC_PUBLIC_FIXTURES, SYNTHETIC_RESTRICTED_FIXTURES


def get_path_traversal_fixtures_root() -> Path:
    """Return the designated root directory for Path Traversal synthetic fixtures."""
    config_folder = current_app.config.get("LAB_PATH_TRAVERSAL_FOLDER")
    if config_folder:
        root = Path(config_folder)
    else:
        root = Path(current_app.instance_path) / "lab_fixtures" / "path_traversal"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def get_public_dir() -> Path:
    """Return the public documents directory where ordinary files reside."""
    public_dir = (get_path_traversal_fixtures_root() / "public").resolve()
    public_dir.mkdir(parents=True, exist_ok=True)
    return public_dir


def get_restricted_dir() -> Path:
    """Return the restricted directory containing synthetic internal fixtures."""
    restricted_dir = (get_path_traversal_fixtures_root() / "restricted").resolve()
    restricted_dir.mkdir(parents=True, exist_ok=True)
    return restricted_dir


def ensure_path_traversal_fixtures() -> None:
    """Seed synthetic public and restricted text files if not already present."""
    public_dir = get_public_dir()
    for filename, content in SYNTHETIC_PUBLIC_FIXTURES.items():
        file_path = public_dir / filename
        if not file_path.exists():
            file_path.write_text(content, encoding="utf-8")

    restricted_dir = get_restricted_dir()
    for filename, content in SYNTHETIC_RESTRICTED_FIXTURES.items():
        file_path = restricted_dir / filename
        if not file_path.exists():
            file_path.write_text(content, encoding="utf-8")


def reset_path_traversal_fixtures() -> None:
    """Clean and re-seed all synthetic fixtures in the dedicated lab directory."""
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
    ensure_path_traversal_fixtures()


def list_public_fixtures() -> list[str]:
    """Return list of filenames in the public fixture directory."""
    ensure_path_traversal_fixtures()
    public_dir = get_public_dir()
    return sorted(f.name for f in public_dir.iterdir() if f.is_file())


def list_restricted_fixtures() -> list[str]:
    """Return list of filenames in the restricted synthetic directory."""
    ensure_path_traversal_fixtures()
    restricted_dir = get_restricted_dir()
    return sorted(f.name for f in restricted_dir.iterdir() if f.is_file())
