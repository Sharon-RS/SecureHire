"""Authenticated Security Lab dashboard, SQLi demo, and placeholders."""

from datetime import datetime, timezone

from flask import abort, flash, make_response, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ...extensions import db
from ...forms.security_lab import (
    ReflectedXssSearchForm,
    SQLiSearchForm,
    SecurityModeForm,
    StoredXssDemoForm,
)
from ...models import LabGigFixture
from ...services.authorization import roles_required
from ...services.demos.sqli import MAX_RESULTS, SAFE_SQLI_PAYLOAD
from ...services.demos.reflected_xss import APPROVED_REFLECTED_XSS_PAYLOAD
from ...services.demos.reflected_xss.content import search_local_content
from ...services.demos.reflected_xss.mitigated import render_mitigated_reflection
from ...services.demos.reflected_xss.vulnerable import render_vulnerable_reflection
from ...services.demos.sqli.mitigated import search_gigs_mitigated
from ...services.demos.sqli.vulnerable import search_gigs_vulnerable
from ...services.demos.stored_xss import APPROVED_STORED_XSS_PAYLOAD
from ...services.demos.stored_xss.mitigated import render_mitigated_demo_value
from ...services.demos.stored_xss.records import store_demo_value, stored_demo_for_user
from ...services.demos.stored_xss.vulnerable import render_vulnerable_demo_value
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
    if vulnerability_key == "stored_xss":
        return _stored_xss_demonstration(module, state)
    if vulnerability_key == "reflected_xss":
        return _reflected_xss_demonstration(module, state)
    return render_template("security_lab/detail.html", module=module, state=state)


@bp.get("/stored-xss")
@login_required
def stored_xss_page():
    """Canonical hyphenated URL for the Stored XSS demonstration page."""
    return module_detail("stored_xss")


@bp.route("/reflected-xss", methods=["GET", "POST"])
@login_required
def reflected_xss_page():
    """Canonical Reflected XSS demonstration page with CSRF-protected POST input."""
    module = get_vulnerability("reflected_xss")
    state = get_module_state("reflected_xss")
    return _reflected_xss_demonstration(module, state)


@bp.post("/sqli")
@login_required
def sqli_search():
    """Accept CSRF-protected SQLi lab searches without accepting a client mode."""
    module = get_vulnerability("sqli")
    state = get_module_state("sqli")
    return _sqli_demonstration(module, state)






@bp.post("/stored-xss")
@login_required
def stored_xss_submit():
    """Store only the approved per-user lab fixture and record a bounded result."""
    module = get_vulnerability("stored_xss")
    state = get_module_state("stored_xss")
    form = StoredXssDemoForm()
    if not form.validate_on_submit():
        response = _stored_xss_demonstration(module, state, form=form)
        response.status_code = 400
        return response

    try:
        store_demo_value(current_user.id, form.payload.data)
    except ValueError:
        abort(400)
    record_lab_run("stored_xss", "passed")
    flash("The local Stored XSS demo value was stored.", "success")
    return redirect(url_for("security_lab.stored_xss_page"))


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


STORED_XSS_VULNERABLE_CSP = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; "
    "frame-ancestors 'none'; form-action 'self'; "
    "script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:"
)


def _stored_xss_demonstration(module, state, form=None):
    """Render the current user's stored lab record through the selected isolated path."""
    entry = stored_demo_for_user(current_user.id)
    if form is None:
        form = StoredXssDemoForm()
        form.payload.data = entry.payload if entry else APPROVED_STORED_XSS_PAYLOAD

    rendered_value = None
    explanation = None
    vulnerable = state["effective_mode"] == "vulnerable"
    if entry is not None:
        if vulnerable and entry.payload == APPROVED_STORED_XSS_PAYLOAD:
            rendered_value = render_vulnerable_demo_value(entry.payload)
            explanation = (
                "The lab deliberately marked the approved stored value as HTML. The browser "
                "interprets the script element and shows the harmless alert."
            )
        else:
            rendered_value = render_mitigated_demo_value(entry.payload)
            explanation = (
                "The server HTML-escaped the stored value for this text-node context. The browser "
                "displays the markup as text instead of creating a script element. Only the exact "
                "approved fixture is eligible for vulnerable rendering."
            )

    response = make_response(
        render_template(
            "security_lab/stored_xss.html",
            module=module,
            state=state,
            form=form,
            entry=entry,
            rendered_value=rendered_value,
            explanation=explanation,
            approved_payload=APPROVED_STORED_XSS_PAYLOAD,
        )
    )
    if vulnerable and entry is not None and entry.payload == APPROVED_STORED_XSS_PAYLOAD:
        # Page-specific exception exists only to make the exact local proof of concept execute.
        # Output encoding remains the mitigation; CSP is defense in depth, not the solution.
        response.headers["Content-Security-Policy"] = STORED_XSS_VULNERABLE_CSP
    return response


REFLECTED_XSS_VULNERABLE_CSP = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; "
    "frame-ancestors 'none'; form-action 'self'; "
    "script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:"
)


def _reflected_xss_demonstration(module, state):
    """Reflect one validated request value through a mode-specific isolated renderer."""
    form = ReflectedXssSearchForm()
    reflected_output = None
    evidence = None
    results = []
    vulnerable = state["effective_mode"] == "vulnerable"

    if request.method == "POST":
        if not form.validate_on_submit():
            response = make_response(render_template(
                "security_lab/reflected_xss.html", module=module, state=state,
                form=form, reflected_output=None, evidence=None, results=[],
                approved_payload=APPROVED_REFLECTED_XSS_PAYLOAD,
            ))
            response.status_code = 400
            return response

        search_term = form.search_term.data.strip()
        if vulnerable:
            reflected_output = render_vulnerable_reflection(search_term)
            classification = (
                "APPROVED SCRIPT MARKUP REFLECTED WITHOUT ENCODING"
                if search_term == APPROVED_REFLECTED_XSS_PAYLOAD
                else "ORDINARY INPUT REFLECTED WITHOUT ENCODING"
            )
        else:
            reflected_output = render_mitigated_reflection(search_term)
            classification = (
                "APPROVED PAYLOAD ENCODED AS TEXT"
                if search_term == APPROVED_REFLECTED_XSS_PAYLOAD
                else "SAFE SEARCH REFLECTION"
            )

        if search_term != APPROVED_REFLECTED_XSS_PAYLOAD:
            results = search_local_content(search_term)

        run = record_lab_run("reflected_xss", "passed")
        evidence = {
            "demonstration_type": (
                "approved harmless proof of concept"
                if search_term == APPROVED_REFLECTED_XSS_PAYLOAD
                else "ordinary synthetic search"
            ),
            "effective_mode": state["effective_mode"],
            "intentionally_reflected": True,
            "classification": classification,
            "result_count": len(results),
            "run_result": run.result,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "attack_input": search_term,
        }

    response = make_response(render_template(
        "security_lab/reflected_xss.html", module=module, state=state,
        form=form, reflected_output=reflected_output, evidence=evidence,
        results=results, approved_payload=APPROVED_REFLECTED_XSS_PAYLOAD,
    ))
    if (
        vulnerable
        and evidence is not None
        and evidence["attack_input"] == APPROVED_REFLECTED_XSS_PAYLOAD
    ):
        # This response-only exception enables the approved local alert. Output
        # encoding remains the mitigation; CSP is defense in depth, not the fix.
        response.headers["Content-Security-Policy"] = REFLECTED_XSS_VULNERABLE_CSP
    return response
