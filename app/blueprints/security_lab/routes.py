"""Authenticated Security Lab dashboard and nonfunctional demo placeholders."""

from flask import abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from ...forms.security_lab import SecurityModeForm
from ...services.authorization import roles_required
from ...services.security_modes import (
    InvalidSecurityMode,
    UnknownVulnerabilityKey,
    get_module_state,
    get_vulnerability,
    list_module_states,
    resolve_effective_mode,
    update_persisted_mode,
)
from . import bp


@bp.get("")
@login_required
@roles_required("admin")
def dashboard():
    states = list_module_states()
    return render_template(
        "security_lab/dashboard.html",
        modules=states,
        has_vulnerable_module=any(state["is_effectively_vulnerable"] for state in states),
        mode_form=SecurityModeForm(),
    )


@bp.get("/<string:vulnerability_key>")
@login_required
def module_detail(vulnerability_key: str):
    try:
        module = get_vulnerability(vulnerability_key)
        state = get_module_state(vulnerability_key)
    except UnknownVulnerabilityKey:
        abort(404)
    return render_template("security_lab/detail.html", module=module, state=state)


@bp.post("/<string:vulnerability_key>/mode")
@login_required
@roles_required("admin")
def change_mode(vulnerability_key: str):
    try:
        module = get_vulnerability(vulnerability_key)
    except UnknownVulnerabilityKey:
        abort(404)

    form = SecurityModeForm()
    if not form.validate_on_submit():
        abort(400)

    try:
        update_persisted_mode(vulnerability_key, form.mode.data, current_user.id)
    except InvalidSecurityMode:
        abort(400)

    effective_mode = resolve_effective_mode(vulnerability_key)
    flash(
        f"{module.name} stored mode updated. Effective mode: {effective_mode.title()}.",
        "success",
    )
    return redirect(url_for("security_lab.dashboard", _anchor=vulnerability_key))
