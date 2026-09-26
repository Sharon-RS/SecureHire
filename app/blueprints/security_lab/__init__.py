"""Security Lab framework routes."""

from flask import Blueprint

bp = Blueprint("security_lab", __name__)

from . import routes  # noqa: E402,F401
