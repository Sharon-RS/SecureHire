"""Server-side CSRF token inspection shared by the two isolated lab paths."""

from flask_wtf.csrf import CSRFError

from ....extensions import csrf


def inspect_submitted_token_state() -> str:
    """Use Flask-WTF's validator and return only a bounded state label."""
    token_was_submitted = bool(csrf._get_csrf_token())
    try:
        csrf.protect()
    except CSRFError:
        return "invalid" if token_was_submitted else "missing"
    return "valid"
