"""Authoritative Security Lab mode, safety-gate, and metadata service.

This module contains framework logic only. It does not execute vulnerability
demonstrations or accept/store proof-of-concept payloads.
"""

from dataclasses import dataclass

from flask import current_app, has_request_context, request
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import LabRun, SecurityAuditLog, SecurityMode
from ..security import is_loopback_address


@dataclass(frozen=True)
class VulnerabilityModule:
    key: str
    name: str
    description: str
    mitigation: str


VULNERABILITIES = (
    VulnerabilityModule(
        "sqli",
        "SQL Injection",
        "Explains how unsafe query construction can expose or change stored records.",
        "Use parameterized ORM queries and authorize every record returned.",
    ),
    VulnerabilityModule(
        "stored_xss",
        "Stored XSS",
        "Shows how stored marketplace reviews can become executable markup when output is unsafe.",
        "HTML-escape review text in its output context and keep Jinja autoescaping enabled.",
    ),
    VulnerabilityModule(
        "reflected_xss",
        "Reflected XSS",
        "Demonstrates how search input returned in the same response can become executable markup.",
        "HTML-escape reflected input for its output context and keep Jinja autoescaping enabled.",
    ),
    VulnerabilityModule(
        "idor_bola",
        "IDOR / BOLA",
        "Explains how changing an object reference can expose another account's records.",
        "Check authorization against the authenticated user for every object operation.",
    ),
    VulnerabilityModule(
        "csrf",
        "CSRF",
        "Explains how a browser can be tricked into sending an unwanted state-changing request.",
        "Require validated CSRF tokens for every state-changing form and keep lab administration protected.",
    ),
    VulnerabilityModule(
        "file_upload",
        "Unrestricted File Upload",
        "Explains why accepting untrusted files without validation can put an application at risk.",
        "Allowlist file types, cap size, store files outside executable web paths, and never execute uploads.",
    ),
    VulnerabilityModule(
        "path_traversal",
        "Path Traversal",
        "Explains how unsafe path handling can escape an intended fixture directory.",
        "Resolve paths and verify containment within the designated directory before access.",
    ),
    VulnerabilityModule(
        "clickjacking",
        "Clickjacking",
        "Explains how a page can be framed to trick a user into clicking hidden controls.",
        "Set a restrictive Content-Security-Policy frame-ancestors directive and X-Frame-Options.",
    ),
    VulnerabilityModule(
        "auth_session",
        "Authentication / Session Security",
        "Explains how weak authentication or session handling can allow account takeover.",
        "Hash passwords, use strong session protections, rotate session state, and set secure cookie attributes.",
    ),
    VulnerabilityModule(
        "security_misconfiguration",
        "Security Misconfiguration",
        "Explains how unsafe defaults or exposed diagnostics can reveal or weaken an application.",
        "Use safe configuration defaults, disable debug mode, and return controlled error pages.",
    ),
)

VULNERABILITY_KEYS = frozenset(module.key for module in VULNERABILITIES)
ALLOWED_MODES = frozenset({"vulnerable", "mitigated"})
ALLOWED_LAB_RESULTS = frozenset({"not_implemented", "passed", "blocked", "failed"})


class UnknownVulnerabilityKey(ValueError):
    """Raised when a request names a module outside the approved allowlist."""


class InvalidSecurityMode(ValueError):
    """Raised when a requested or stored mode is not recognized."""


class InvalidLabRunResult(ValueError):
    """Raised when a lab result is outside the bounded result vocabulary."""


class AdministratorRequired(PermissionError):
    """Raised when a non-administrator attempts a server-side mode change."""


def get_vulnerability(key: str) -> VulnerabilityModule:
    if not isinstance(key, str) or key not in VULNERABILITY_KEYS:
        raise UnknownVulnerabilityKey("Unknown Security Lab module.")
    return next(module for module in VULNERABILITIES if module.key == key)


def get_persisted_mode(key: str) -> str:
    get_vulnerability(key)
    setting = SecurityMode.query.filter_by(vulnerability_key=key).one_or_none()
    if setting is None or setting.mode not in ALLOWED_MODES:
        return "mitigated"
    return setting.mode


def _lab_explicitly_enabled() -> bool:
    # Config parsing converts a narrow set of explicit environment values to bool.
    # Unexpected types and missing settings fail closed.
    return current_app.config.get("LAB_ENABLE", False) is True


def _nonproduction_environment() -> bool:
    environment = current_app.config.get("APP_ENV")
    return isinstance(environment, str) and environment.lower() in {"development", "testing"}


def _request_is_loopback() -> bool:
    # REMOTE_ADDR is supplied by the accepted socket. Host and proxy headers are ignored.
    return has_request_context() and is_loopback_address(request.remote_addr)


def vulnerable_mode_gate_open() -> bool:
    """Return true only when explicit lab opt-in, nonproduction, and loopback all hold."""
    return (
        _lab_explicitly_enabled()
        and _nonproduction_environment()
        and _request_is_loopback()
    )


def _effective_mode_from_persisted(stored_mode: str) -> str:
    if stored_mode != "vulnerable":
        return "mitigated"
    if not vulnerable_mode_gate_open():
        return "mitigated"
    return "vulnerable"


def resolve_effective_mode(key: str) -> str:
    """Resolve the persisted setting through the centralized fail-closed safety gate."""
    return _effective_mode_from_persisted(get_persisted_mode(key))


def get_module_state(key: str) -> dict[str, object]:
    module = get_vulnerability(key)
    stored_mode = get_persisted_mode(key)
    effective_mode = _effective_mode_from_persisted(stored_mode)
    return {
        "key": module.key,
        "name": module.name,
        "description": module.description,
        "mitigation": module.mitigation,
        "stored_mode": stored_mode,
        "effective_mode": effective_mode,
        "protection_status": "PROTECTED" if effective_mode == "mitigated" else "VULNERABLE MODE ACTIVE",
        "is_effectively_vulnerable": effective_mode == "vulnerable",
    }


def list_module_states() -> list[dict[str, object]]:
    return [get_module_state(module.key) for module in VULNERABILITIES]


def update_persisted_mode(key: str, mode: str, changed_by: int) -> str:
    """Atomically update one stored mode and its audit record; return its previous mode."""
    get_vulnerability(key)
    if not isinstance(mode, str) or mode not in ALLOWED_MODES:
        raise InvalidSecurityMode("Choose a valid security mode.")
    if not isinstance(changed_by, int):
        raise ValueError("A valid administrator identity is required.")
    from ..models import User

    actor = db.session.get(User, changed_by)
    if actor is None or actor.role != "admin" or actor.status != "active":
        raise AdministratorRequired("An active administrator is required to change modes.")

    setting = (
        SecurityMode.query.filter_by(vulnerability_key=key)
        .with_for_update()
        .one_or_none()
    )
    if setting is None:
        setting = SecurityMode(vulnerability_key=key, mode="mitigated")
        db.session.add(setting)
        db.session.flush()

    previous_mode = setting.mode if setting.mode in ALLOWED_MODES else "mitigated"
    setting.mode = mode
    setting.updated_by = changed_by
    db.session.add(
        SecurityAuditLog(
            vulnerability_key=key,
            previous_mode=previous_mode,
            new_mode=mode,
            changed_by=changed_by,
        )
    )
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise
    return previous_mode


def record_lab_run(key: str, result: str) -> LabRun:
    """Record a bounded status only; the schema intentionally has no payload field."""
    get_vulnerability(key)
    if not isinstance(result, str) or result not in ALLOWED_LAB_RESULTS:
        raise InvalidLabRunResult("Choose an approved lab result status.")

    effective_mode = resolve_effective_mode(key)
    setting = SecurityMode.query.filter_by(vulnerability_key=key).one_or_none()
    if setting is None:
        db.session.add(SecurityMode(vulnerability_key=key, mode="mitigated"))
        db.session.flush()

    record = LabRun(
        vulnerability_key=key,
        mode=effective_mode,
        result=result,
    )
    db.session.add(record)
    db.session.commit()
    return record
