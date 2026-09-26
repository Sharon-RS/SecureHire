"""Marketplace routes."""

from flask import Blueprint

bp = Blueprint("marketplace", __name__)

from . import routes  # noqa: E402,F401
