"""Pure-Python file inspection and validation routines."""

import os
from pathlib import PurePath
import uuid

from . import ALLOWED_EXTENSIONS


def get_file_extension(filename: str) -> str:
    """Extract and lowercase the final file extension, including the dot."""
    if not filename or "." not in filename:
        return ""
    ext = os.path.splitext(filename)[1].lower().strip()
    return ext


def validate_extension(filename: str) -> bool:
    """Check whether the file extension is on the approved allowlist."""
    ext = get_file_extension(filename)
    return ext in ALLOWED_EXTENSIONS


def validate_magic_bytes(content: bytes, ext: str) -> tuple[bool, str]:
    """Inspect leading bytes to verify standard file signatures.

    Returns a tuple of (is_valid, detected_mime_type).
    """
    ext = ext.lower().strip()
    if not content:
        return False, "application/x-empty"

    if ext == ".png":
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return True, "image/png"
        return False, detect_mime_type(content, "file" + ext)

    if ext in {".jpg", ".jpeg"}:
        if content.startswith(b"\xff\xd8\xff"):
            return True, "image/jpeg"
        return False, detect_mime_type(content, "file" + ext)

    if ext == ".pdf":
        if content.startswith(b"%PDF-"):
            return True, "application/pdf"
        return False, detect_mime_type(content, "file" + ext)

    if ext == ".txt":
        # Plain text must be valid UTF-8/ASCII without binary NUL bytes
        if b"\x00" in content[:1024]:
            return False, "application/octet-stream"
        try:
            content.decode("utf-8")
            return True, "text/plain"
        except UnicodeDecodeError:
            return False, "application/octet-stream"

    return False, detect_mime_type(content, "file" + ext)


def detect_mime_type(content: bytes, filename: str) -> str:
    """Heuristic identification of content type based on signatures and extensions."""
    if not content:
        return "application/x-empty"

    # Known binary headers
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if content.startswith(b"%PDF-"):
        return "application/pdf"
    if content.startswith(b"GIF87a") or content.startswith(b"GIF89a"):
        return "image/gif"
    if content.startswith(b"PK\x03\x04"):
        return "application/zip"
    if content.startswith(b"<?php") or b"<?php" in content[:256]:
        return "application/x-php"
    if content.startswith(b"#!/bin/") or content.startswith(b"#!/usr/bin/"):
        return "text/x-shellscript"

    # Fallback to extension heuristic
    ext = get_file_extension(filename)
    extension_map = {
        ".php": "application/x-php",
        ".py": "text/x-python",
        ".sh": "text/x-shellscript",
        ".exe": "application/x-dosexec",
        ".html": "text/html",
        ".htm": "text/html",
        ".svg": "image/svg+xml",
        ".js": "application/javascript",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".pdf": "application/pdf",
        ".txt": "text/plain",
    }
    if ext in extension_map:
        return extension_map[ext]

    # Check if decodable as plain text
    if b"\x00" not in content[:1024]:
        try:
            content.decode("utf-8")
            return "text/plain"
        except UnicodeDecodeError:
            pass

    return "application/octet-stream"


def sanitize_storage_filename(original_filename: str) -> str:
    """Generate a collision-free UUID storage filename preserving the validated extension."""
    ext = get_file_extension(original_filename)
    if not ext:
        ext = ".bin"
    return f"{uuid.uuid4().hex}{ext}"
