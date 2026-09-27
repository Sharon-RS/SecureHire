"""Authenticated Security Lab dashboard, SQLi demo, and placeholders."""

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ...extensions import db
from ...forms.security_lab import SQLiSearchForm, SecurityModeForm
from ...models import LabGigFixture
from ...services.authorization import roles_required
from ...services.demos.sqli import MAX_RESULTS, SAFE_SQLI_PAYLOAD
from ...services.demos.sqli.mitigated import search_gigs_mitigated
from ...services.demos.sqli.vulnerable import search_gigs_vulnerable
from ...services.security_modes import (
    InvalidSecurityMode,
    UnknownVulnerabilityKey,
    get_module_state,
    get_vulnerability,
    list_module_states,
    record_lab_run,
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
    if vulnerability_key == "sqli":
        return _sqli_demonstration(module, state)
    return render_template("security_lab/detail.html", module=module, state=state)

@bp.post("/sqli")
@login_required
def sqli_search():
    """Accept CSRF-protected SQLi lab searches without accepting a client mode."""
    module = get_vulnerability("sqli")
    state = get_module_state("sqli")
    return _sqli_demonstration(module, state)



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


def _sqli_demonstration(module, state):
    """Render and run the SQLi lesson against the dedicated synthetic fixture table."""
    form = SQLiSearchForm()
    results = []
    evidence = None
    fixture_count = db.session.query(LabGigFixture).count()

    if request.method == "POST":
        if not form.validate_on_submit():
            abort(400)

        search_term = form.search_term.data
        effective_mode = state["effective_mode"]
        safe_matches = search_gigs_mitigated(search_term)
        if effective_mode == "vulnerable":
            results = search_gigs_vulnerable(search_term)
        else:
            results = safe_matches

        if search_term == SAFE_SQLI_PAYLOAD and effective_mode == "vulnerable":
            fixture_ids = [
                fixture_id
                for (fixture_id,) in db.session.query(LabGigFixture.id)
                .order_by(LabGigFixture.id.asc())
                .limit(MAX_RESULTS)
                .all()
            ]
            expected_ids = fixture_ids
            expected_behavior = (
                "The unsafe OR expression broadens the search to every synthetic lab fixture "
                "(up to the fixed result limit)."
            )
        elif search_term == SAFE_SQLI_PAYLOAD:
            expected_ids = [int(match["id"]) for match in safe_matches]
            expected_behavior = (
                "The approved SQLi string is a bound literal and should match no fixture title "
                "or category."
            )
        else:
            expected_ids = [int(match["id"]) for match in safe_matches]
            expected_behavior = "Only an exact synthetic title or category match should appear."

        actual_ids = [int(match["id"]) for match in results]
        expected_met = actual_ids == expected_ids
        actual_behavior = (
            f"Returned {len(results)} of {fixture_count} synthetic fixtures; "
            + (
                "the result matched the expected behavior."
                if expected_met
                else "the result did not match the expected behavior."
            )
        )
        run = record_lab_run("sqli", "passed" if expected_met else "failed")
        evidence = {
            "search_term": search_term,
            "effective_mode": effective_mode,
            "result_count": len(results),
            "fixture_count": fixture_count,
            "expected_behavior": expected_behavior,
            "actual_behavior": actual_behavior,
            "mitigation_state": (
                "Active: the ORM treats the search string as a literal value."
                if effective_mode == "mitigated"
                else "Disabled for this gated lab run; the isolated unsafe SELECT is active."
            ),
            "run_result": run.result,
        }

    return render_template(
        "security_lab/sqli.html",
        module=module,
        state=state,
        form=form,
        results=results,
        evidence=evidence,
        fixture_count=fixture_count,
        max_results=MAX_RESULTS,
        safe_payload=SAFE_SQLI_PAYLOAD,
    )
