"""SecureHire application factory."""

import os

from flask import Flask, abort, render_template, request
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFError

from .config import CONFIGS
from .extensions import csrf, db, login_manager
from .security import is_allowed_local_host, is_loopback_address


def create_app(config_name: str | None = None, test_config: dict | None = None) -> Flask:
    """Create a SecureHire app; only local-development and isolated-test modes are supported."""
    from . import models  # noqa: F401 - ensure model metadata is registered

    name = (config_name or os.environ.get("APP_ENV", "development")).lower()
    if name == "production":
        raise RuntimeError("SecureHire is a localhost-only academic application.")
    if name not in CONFIGS:
        raise RuntimeError(f"Unsupported APP_ENV: {name}")

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(CONFIGS[name])
    if test_config:
        app.config.update(test_config)

    if app.config.get("APP_ENV") == "production":
        raise RuntimeError("Production mode is not supported.")
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY is required. Copy .env.example to .env and set a local secret.")
    if not app.config.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError("DATABASE_URL is required for development.")

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    Migrate(app, db, render_as_batch=True)

    from .blueprints.auth import bp as auth_bp
    from .blueprints.main import bp as main_bp
    from .blueprints.marketplace import bp as marketplace_bp
    from .blueprints.security_lab import bp as security_lab_bp
    from .forms.auth import LogoutForm

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(marketplace_bp)
    app.register_blueprint(security_lab_bp, url_prefix="/security-lab")

    @app.context_processor
    def provide_shared_forms():
        return {"logout_form": LogoutForm()}

    @app.before_request
    def enforce_local_access():
        if not app.config.get("ENFORCE_LOOPBACK", True):
            return None
        # REMOTE_ADDR is populated by the accepted socket. Forwarded headers are ignored.
        if not is_loopback_address(request.remote_addr):
            abort(403)
        # Host is only allowlisted as a DNS-rebinding defense, never trusted as locality proof.
        if not is_allowed_local_host(request.host, tuple(app.config["LOCAL_HOSTS"])):
            abort(400)
        return None

    @app.after_request
    def apply_security_headers(response):
        from .services.security_modes import resolve_effective_mode, vulnerable_mode_gate_open

        is_clickjacking_target = (
            request.endpoint in {"security_lab.clickjacking_target", "security_lab.clickjacking_target_action"}
            or request.path == "/security-lab/clickjacking/target"
        )
        if (
            is_clickjacking_target
            and vulnerable_mode_gate_open()
            and resolve_effective_mode("clickjacking") == "vulnerable"
        ):
            # Educational exception strictly scoped to the Clickjacking demonstration target:
            # Omit X-Frame-Options and frame-ancestors 'none' when vulnerable mode is gate-approved.
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; base-uri 'self'; object-src 'none'; "
                "form-action 'self'; script-src 'self'; "
                "style-src 'self'; img-src 'self' data:",
            )
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
            response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            response.headers.pop("X-Frame-Options", None)
            return response

        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'self'; script-src 'self'; "
            "style-src 'self'; img-src 'self' data:",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        return render_template("errors/400.html"), 400

    @app.errorhandler(400)
    def bad_request(_error):
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(409)
    def conflict(_error):
        return render_template("errors/409.html"), 409

    @app.errorhandler(500)
    def internal_error(_error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    return app


@login_manager.user_loader
def load_user(user_id: str):
    from .models import User

    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
