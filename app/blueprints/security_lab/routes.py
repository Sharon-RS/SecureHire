"""Authenticated Security Lab dashboard, SQLi demo, and placeholders."""

from datetime import datetime, timezone

from flask import abort, flash, make_response, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_required

from ...extensions import csrf as csrf_protection, db
from ...forms.security_lab import (
    AuthSessionInspectTokenForm,
    AuthSessionReplayTokenForm,
    AuthSessionResetForm,
    AuthSessionSimulateLoginForm,
    AuthSessionSimulateLogoutForm,
    ClickjackingResetForm,
    ClickjackingTargetActionForm,
    CsrfFixtureResetForm,
    FileUploadDemoForm,
    FileUploadResetForm,
    IdorBolaReadForm,
    PathTraversalDemoForm,
    PathTraversalResetForm,
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
from ...services.demos.idor_bola.mitigated import read_proposal_mitigated
from ...services.demos.idor_bola.scenario import persona_label_for_email, scenario_proposals
from ...services.demos.idor_bola.vulnerable import read_proposal_vulnerable
from ...services.demos.csrf import (
    LAB_CSRF_REQUESTER_LABEL,
    LAB_CSRF_TARGET_LABEL,
)
from ...services.demos.csrf.actions import accept_fixture_proposal, reset_fixture_proposal
from ...services.demos.csrf.fixture import csrf_scenario_proposal
from ...services.demos.csrf.mitigated import require_valid_token
from ...services.demos.csrf.vulnerable import accept_without_token_requirement
from ...services.demos.file_upload import (
    ALLOWED_EXTENSIONS,
    DEMONSTRATION_SAMPLES,
    MAX_FILE_SIZE_BYTES,
    SAMPLE_MAP,
)
from ...services.demos.file_upload.mitigated import process_mitigated_upload
from ...services.demos.file_upload.storage import (
    delete_user_uploads,
    get_file_for_download,
    get_user_active_upload,
)
from ...services.demos.file_upload.vulnerable import process_vulnerable_upload
from ...services.demos.path_traversal import (
    DEFAULT_DOCUMENT,
    PRESET_MAP,
    TRAVERSAL_PRESETS,
)
from ...services.demos.path_traversal.fixtures import (
    list_public_fixtures,
    list_restricted_fixtures,
    reset_path_traversal_fixtures,
)
from ...services.demos.path_traversal.mitigated import process_mitigated_read
from ...services.demos.path_traversal.vulnerable import process_vulnerable_read
from ...services.demos.clickjacking import (
    CLICKJACKING_DEMO_DESCRIPTION,
    CLICKJACKING_DEMO_TITLE,
    DECOY_BUTTON_LABEL,
    MITIGATED_FRAME_ANCESTORS,
    MITIGATED_X_FRAME_OPTIONS,
    REAL_BUTTON_LABEL,
)
from ...services.demos.clickjacking.mitigated import get_mitigated_clickjacking_evidence
from ...services.demos.clickjacking.vulnerable import get_vulnerable_clickjacking_evidence
from ...services.demos.auth_session import (
    AUTH_SESSION_COOKIE_NAME,
    AUTH_SESSION_DEMO_DESCRIPTION,
    AUTH_SESSION_DEMO_TITLE,
    INITIAL_PRE_AUTH_TOKEN,
    LAB_AUTH_SESSION_CONTRACT_SUMMARY,
    LAB_AUTH_SESSION_USER_EMAIL,
    LAB_AUTH_SESSION_USER_NAME,
    LABEL_SIMULATED_TAKEOVER,
)
from ...services.demos.auth_session.store import (
    get_active_session,
    get_pre_auth_token,
    get_session,
    get_store_snapshot,
    reset_auth_session_store,
)
from ...services.demos.auth_session.vulnerable import (
    execute_vulnerable_inspect,
    execute_vulnerable_login,
    execute_vulnerable_logout,
)
from ...services.demos.auth_session.mitigated import (
    execute_mitigated_inspect,
    execute_mitigated_login,
    execute_mitigated_logout,
)
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
    if vulnerability_key == "idor_bola":
        return _idor_bola_demonstration(module, state)
    if vulnerability_key == "csrf":
        return _render_csrf_page(module, state)
    if vulnerability_key == "file_upload":
        return _render_file_upload_page(module, state)
    if vulnerability_key == "path_traversal":
        return _render_path_traversal_page(module, state)
    if vulnerability_key == "clickjacking":
        return _render_clickjacking_page(module, state)
    if vulnerability_key == "auth_session":
        return _render_auth_session_page(module, state)
    return render_template("security_lab/detail.html", module=module, state=state)


@bp.get("/csrf")
@login_required
def csrf_page():
    """Display the CSRF lesson; only its dedicated run endpoint is exempt."""
    module = get_vulnerability("csrf")
    state = get_module_state("csrf")
    return _render_csrf_page(module, state)


@bp.post("/csrf/run")
@login_required
@csrf_protection.exempt
def csrf_demo_run():
    """Run a fixed proposal action with mode-specific server-side token enforcement."""
    module = get_vulnerability("csrf")
    state = get_module_state("csrf")
    proposal = csrf_scenario_proposal()
    if proposal is None:
        return _render_csrf_page(module, state, status_code=503)
    if current_user.id != proposal.gig.owner_id:
        return _render_csrf_page(module, state, status_code=403)

    if state["effective_mode"] == "vulnerable":
        token_decision = accept_without_token_requirement()
    else:
        token_decision = require_valid_token()

    action_result = None
    if token_decision.accepted:
        action_result = accept_fixture_proposal(proposal)

    if not token_decision.accepted:
        status_code = 400
    elif action_result is not None and action_result.changed:
        status_code = 200
    else:
        status_code = 409

    if state["effective_mode"] == "vulnerable":
        expected_behavior = (
            f"Vulnerable mode accepts the fixed synthetic action with a "
            f"{token_decision.token_state} token state."
        )
        mitigation_status = "CSRF token enforcement is intentionally bypassed for this gated lab request."
    elif token_decision.token_state == "valid":
        expected_behavior = "Mitigated mode accepts a valid server-validated token."
        mitigation_status = "Server-side CSRF token validation is active."
    else:
        expected_behavior = (
            f"Mitigated mode rejects a {token_decision.token_state} token and leaves the fixture unchanged."
        )
        mitigation_status = "Server-side CSRF token validation is active."

    if not token_decision.accepted:
        observed_behavior = (
            f"The server returned HTTP {status_code}; proposal contents and state were not changed."
        )
        state_before = proposal.status
        state_after = proposal.status
    elif action_result is not None and action_result.changed:
        observed_behavior = (
            "The server accepted the fixture action and changed its status from Pending to Accepted."
        )
        state_before = action_result.state_before
        state_after = action_result.state_after
    else:
        observed_behavior = (
            "The server returned HTTP 409 because the fixture proposal is not pending. "
            "Reset the fixture before another state-change attempt."
        )
        state_before = action_result.state_before if action_result else proposal.status
        state_after = action_result.state_after if action_result else proposal.status

    run = record_lab_run(
        "csrf",
        "passed" if status_code in {200, 400} else "blocked",
    )
    evidence = {
        "effective_mode": state["effective_mode"],
        "token_state": token_decision.token_state,
        "http_status": status_code,
        "state_changed": bool(action_result and action_result.changed),
        "state_before": state_before,
        "state_after": state_after,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior,
        "mitigation_status": mitigation_status,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_result": run.result,
    }
    return _render_csrf_page(module, state, evidence=evidence, status_code=status_code)


@bp.post("/csrf/reset")
@login_required
def csrf_fixture_reset():
    """Reset only the known synthetic proposal; global Flask-WTF CSRF stays active."""
    proposal = csrf_scenario_proposal()
    if proposal is None:
        abort(503)
    if current_user.id != proposal.gig.owner_id:
        abort(403)

    form = CsrfFixtureResetForm()
    if not form.validate_on_submit():
        abort(400)
    changed = reset_fixture_proposal(proposal)
    flash(
        "Synthetic CSRF proposal reset to Pending."
        if changed
        else "Synthetic CSRF proposal is already Pending.",
        "info",
    )
    return redirect(url_for("security_lab.csrf_page"))


@bp.get("/file-upload")
@login_required
def file_upload_page():
    """Display the Unrestricted File Upload lesson and upload controls."""
    module = get_vulnerability("file_upload")
    state = get_module_state("file_upload")
    return _render_file_upload_page(module, state)


@bp.post("/file-upload")
@login_required
def file_upload_submit():
    """Accept an upload or demonstration sample and process through effective mode."""
    module = get_vulnerability("file_upload")
    state = get_module_state("file_upload")
    form = FileUploadDemoForm()

    if not form.validate_on_submit():
        return _render_file_upload_page(module, state, form=form, status_code=400)

    sample_case = form.sample_case.data
    filename = None
    content = None

    if sample_case != "custom" and sample_case in SAMPLE_MAP:
        sample = SAMPLE_MAP[sample_case]
        filename = sample.filename
        content = sample.content
    elif form.file.data:
        uploaded_file = form.file.data
        filename = uploaded_file.filename
        content = uploaded_file.read()
    else:
        flash("Please select a demonstration sample or choose a file to upload.", "warning")
        return _render_file_upload_page(module, state, form=form, status_code=400)

    if not filename:
        flash("Filename cannot be empty.", "danger")
        return _render_file_upload_page(module, state, form=form, status_code=400)

    is_vulnerable = state["effective_mode"] == "vulnerable"
    if is_vulnerable:
        success, evidence, status_code = process_vulnerable_upload(
            current_user.id, filename, content
        )
    else:
        success, evidence, status_code = process_mitigated_upload(
            current_user.id, filename, content
        )

    run_result = "passed" if success else "blocked"
    run = record_lab_run("file_upload", run_result)
    evidence["run_result"] = run.result

    return _render_file_upload_page(
        module, state, form=form, evidence=evidence, status_code=status_code
    )


@bp.get("/file-upload/download/<path:filename>")
@login_required
def file_upload_download(filename: str):
    """Safely serve the uploaded demonstration file as a download attachment."""
    try:
        file_path, safe_name = get_file_for_download(current_user.id, filename)
    except (FileNotFoundError, PermissionError, ValueError):
        abort(404)

    response = send_file(
        file_path,
        as_attachment=True,
        download_name=safe_name,
        mimetype="application/octet-stream",
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@bp.post("/file-upload/reset")
@login_required
def file_upload_reset():
    """Reset and delete current user's uploaded demonstration files."""
    form = FileUploadResetForm()
    if not form.validate_on_submit():
        abort(400)

    deleted = delete_user_uploads(current_user.id)
    if deleted:
        flash("Uploaded demonstration files cleared.", "info")
    else:
        flash("No demonstration files were present.", "info")
    return redirect(url_for("security_lab.file_upload_page"))


@bp.get("/path-traversal")
@login_required
def path_traversal_page():
    """Display the Path Traversal lesson and document viewer controls."""
    module = get_vulnerability("path_traversal")
    state = get_module_state("path_traversal")
    return _render_path_traversal_page(module, state)


@bp.post("/path-traversal")
@login_required
def path_traversal_submit():
    """Process a document view request through the effective security mode."""
    module = get_vulnerability("path_traversal")
    state = get_module_state("path_traversal")
    form = PathTraversalDemoForm()

    if not form.validate_on_submit():
        return _render_path_traversal_page(module, state, form=form, status_code=400)

    preset_case = form.preset_case.data
    requested_path = ""
    if preset_case != "custom" and preset_case in PRESET_MAP:
        requested_path = PRESET_MAP[preset_case].path
    else:
        requested_path = (form.document_path.data or "").strip()

    if not requested_path:
        flash("Please select a demonstration preset or enter a document path.", "warning")
        return _render_path_traversal_page(module, state, form=form, status_code=400)

    is_vulnerable = state["effective_mode"] == "vulnerable"
    if is_vulnerable:
        success, evidence, status_code = process_vulnerable_read(requested_path)
    else:
        success, evidence, status_code = process_mitigated_read(requested_path)

    run_result = "passed" if success else "blocked"
    run = record_lab_run("path_traversal", run_result)
    evidence["run_result"] = run.result

    return _render_path_traversal_page(
        module, state, form=form, evidence=evidence, status_code=status_code
    )


@bp.post("/path-traversal/reset")
@login_required
def path_traversal_reset():
    """Reset and re-seed all synthetic path traversal fixtures."""
    form = PathTraversalResetForm()
    if not form.validate_on_submit():
        abort(400)

    reset_path_traversal_fixtures()
    flash("Path traversal synthetic fixtures restored to initial state.", "info")
    return redirect(url_for("security_lab.path_traversal_page"))


@bp.get("/clickjacking")
@login_required
def clickjacking_page():
    """Display the Clickjacking lesson and interactive visualizer."""
    module = get_vulnerability("clickjacking")
    state = get_module_state("clickjacking")
    return _render_clickjacking_page(module, state)


@bp.get("/clickjacking/target")
@login_required
def clickjacking_target():
    """The synthetic target page intended for framing demonstration."""
    module = get_vulnerability("clickjacking")
    state = get_module_state("clickjacking")
    form = ClickjackingTargetActionForm()
    endorsements = session.get("synthetic_endorsements", 0)
    return render_template(
        "security_lab/clickjacking_target.html",
        module=module,
        state=state,
        form=form,
        endorsements=endorsements,
        button_label=REAL_BUTTON_LABEL,
    )


@bp.post("/clickjacking/target")
@login_required
def clickjacking_target_action():
    """Handle 1-click synthetic endorsement action."""
    module = get_vulnerability("clickjacking")
    state = get_module_state("clickjacking")
    form = ClickjackingTargetActionForm()
    if not form.validate_on_submit():
        abort(400)

    session["synthetic_endorsements"] = session.get("synthetic_endorsements", 0) + 1
    record_lab_run("clickjacking", "passed")
    flash("Synthetic freelancer skill endorsement registered!", "success")
    return redirect(url_for("security_lab.clickjacking_target"))


@bp.get("/clickjacking/framing-test")
@login_required
def clickjacking_framing_test():
    """Standalone minimal framing harness for automated and browser testing."""
    module = get_vulnerability("clickjacking")
    state = get_module_state("clickjacking")
    return render_template(
        "security_lab/clickjacking_framing_test.html",
        module=module,
        state=state,
    )


@bp.post("/clickjacking/reset")
@login_required
def clickjacking_reset():
    """Reset the synthetic endorsement counter."""
    form = ClickjackingResetForm()
    if not form.validate_on_submit():
        abort(400)

    session["synthetic_endorsements"] = 0
    flash("Synthetic endorsement counter reset to 0.", "info")
    return redirect(url_for("security_lab.clickjacking_page"))



@bp.route("/idor", methods=["GET", "POST"])
@login_required
def idor_bola_page():
    """Canonical read-only IDOR/BOLA page; mode is resolved server-side."""
    module = get_vulnerability("idor_bola")
    state = get_module_state("idor_bola")
    return _idor_bola_demonstration(module, state)


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


def _render_csrf_page(module, state, evidence=None, status_code=200):
    """Render the CSRF lab with bounded evidence and no token values."""
    proposal = csrf_scenario_proposal()
    can_run = proposal is not None and current_user.id == proposal.gig.owner_id
    return make_response(
        render_template(
            "security_lab/csrf.html",
            module=module,
            state=state,
            proposal=proposal,
            requester_label=LAB_CSRF_REQUESTER_LABEL,
            target_label=LAB_CSRF_TARGET_LABEL,
            can_run=can_run,
            reset_form=CsrfFixtureResetForm(),
            evidence=evidence,
        ),
        status_code,
    )


def _render_file_upload_page(module, state, form=None, evidence=None, status_code=200):
    """Render the File Upload demonstration page with bounded evidence."""
    if form is None:
        form = FileUploadDemoForm()
    active_file = get_user_active_upload(current_user.id)
    reset_form = FileUploadResetForm()

    return make_response(
        render_template(
            "security_lab/file_upload.html",
            module=module,
            state=state,
            form=form,
            reset_form=reset_form,
            active_file=active_file,
            evidence=evidence,
            samples=DEMONSTRATION_SAMPLES,
            allowed_extensions=sorted(ALLOWED_EXTENSIONS),
            max_size_kb=MAX_FILE_SIZE_BYTES // 1024,
        ),
        status_code,
    )


def _render_path_traversal_page(module, state, form=None, evidence=None, status_code=200):
    """Render the Path Traversal demonstration page with bounded evidence."""
    if form is None:
        form = PathTraversalDemoForm()
        form.document_path.data = DEFAULT_DOCUMENT
    reset_form = PathTraversalResetForm()
    public_files = list_public_fixtures()
    restricted_files = list_restricted_fixtures()

    return make_response(
        render_template(
            "security_lab/path_traversal.html",
            module=module,
            state=state,
            form=form,
            reset_form=reset_form,
            evidence=evidence,
            presets=TRAVERSAL_PRESETS,
            public_files=public_files,
            restricted_files=restricted_files,
        ),
        status_code,
    )


def _render_clickjacking_page(module, state, status_code=200):
    """Render the Clickjacking lesson page with interactive framing simulation."""
    reset_form = ClickjackingResetForm()
    is_vulnerable = state["effective_mode"] == "vulnerable"
    evidence = (
        get_vulnerable_clickjacking_evidence()
        if is_vulnerable
        else get_mitigated_clickjacking_evidence()
    )
    endorsements = session.get("synthetic_endorsements", 0)

    return make_response(
        render_template(
            "security_lab/clickjacking.html",
            module=module,
            state=state,
            reset_form=reset_form,
            evidence=evidence,
            endorsements=endorsements,
            decoy_label=DECOY_BUTTON_LABEL,
            real_label=REAL_BUTTON_LABEL,
            demo_title=CLICKJACKING_DEMO_TITLE,
            demo_description=CLICKJACKING_DEMO_DESCRIPTION,
            mitigated_xfo=MITIGATED_X_FRAME_OPTIONS,
            mitigated_csp=MITIGATED_FRAME_ANCESTORS,
        ),
        status_code,
    )


def _idor_bola_demonstration(module, state):
    """Run the isolated proposal lookup and display bounded security evidence."""
    proposals = scenario_proposals()
    form = IdorBolaReadForm()
    form.target_proposal_id.choices = [
        (str(proposal.id), f"{persona_label_for_email(proposal.freelancer.email)} — synthetic proposal")
        for proposal in proposals
    ]
    if request.method == "GET" and proposals:
        suggested = next(
            (proposal for proposal in proposals if proposal.freelancer_id != current_user.id),
            proposals[0],
        )
        form.target_proposal_id.data = suggested.id

    requester = persona_label_for_email(current_user.email)
    selected_owner = None
    proposal_result = None
    evidence = None
    response_status = 200

    if request.method == "POST" and not proposals:
        response_status = 503
    elif request.method == "POST":
        if not form.validate_on_submit():
            response_status = 400
        else:
            target_id = form.target_proposal_id.data
            selected = next((proposal for proposal in proposals if proposal.id == target_id), None)
            if selected is None:
                response_status = 400
            else:
                selected_owner = persona_label_for_email(selected.freelancer.email)
                is_cross_user = selected.freelancer_id != current_user.id
                if state["effective_mode"] == "vulnerable":
                    proposal_result = read_proposal_vulnerable(target_id, proposals)
                    allowed = proposal_result is not None
                else:
                    decision = read_proposal_mitigated(target_id, current_user.id, proposals)
                    proposal_result = decision.proposal
                    allowed = decision.allowed

                response_status = 200 if allowed else 403
                if state["effective_mode"] == "vulnerable":
                    finding = (
                        "The isolated lookup returned another synthetic user's proposal because "
                        "it intentionally omitted the object-owner authorization check."
                        if is_cross_user and allowed
                        else "The synthetic proposal was read through the isolated vulnerable lookup."
                    )
                elif allowed:
                    finding = "The server confirmed that the authenticated requester owns this proposal."
                else:
                    finding = (
                        "The server denied the cross-user request before returning proposal contents."
                    )

                run = record_lab_run("idor_bola", "passed")
                evidence = {
                    "effective_mode": state["effective_mode"],
                    "requester": requester,
                    "target_owner": selected_owner,
                    "decision": "ALLOWED" if allowed else "DENIED",
                    "http_status": response_status,
                    "finding": finding,
                    "run_result": run.result,
                }

    return make_response(
        render_template(
            "security_lab/idor_bola.html",
            module=module,
            state=state,
            form=form,
            scenario_ready=len(proposals) == 2,
            requester=requester,
            selected_owner=selected_owner,
            proposal_result=proposal_result,
            evidence=evidence,
        ),
        response_status,
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


@bp.get("/auth-session")
@bp.get("/auth_session")
@login_required
def auth_session_page():
    """Display the isolated Authentication & Session Security lab."""
    module = get_vulnerability("auth_session")
    state = get_module_state("auth_session")
    return _render_auth_session_page(module, state)


@bp.post("/auth-session/simulate-login")
@login_required
def auth_session_simulate_login():
    """Simulate logging the synthetic consultant into the session."""
    module = get_vulnerability("auth_session")
    state = get_module_state("auth_session")
    form = AuthSessionSimulateLoginForm()
    if not form.validate_on_submit():
        abort(400)

    pre_auth_token = get_pre_auth_token()
    vulnerable = state["effective_mode"] == "vulnerable"
    if vulnerable:
        result = execute_vulnerable_login(pre_auth_token)
    else:
        result = execute_mitigated_login(pre_auth_token)

    run = record_lab_run("auth_session", "passed")
    evidence = {
        "action": "simulate_login",
        "effective_mode": state["effective_mode"],
        "pre_auth_token": result.pre_auth_token,
        "effective_token": result.effective_token,
        "session_rotated": result.session_rotated,
        "cookie_httponly": result.cookie_httponly,
        "cookie_samesite": result.cookie_samesite or "None",
        "evidence_summary": result.evidence_summary,
        "classification": result.classification,
        "run_result": run.result,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return _render_auth_session_page(
        module, state, evidence=evidence, active_token=result.effective_token
    )


@bp.post("/auth-session/inspect-token")
@login_required
def auth_session_inspect_token():
    """Inspect what access a given synthetic session token grants."""
    module = get_vulnerability("auth_session")
    state = get_module_state("auth_session")
    form = AuthSessionInspectTokenForm()
    if not form.validate_on_submit():
        abort(400)

    token = (form.token.data or "").strip() or get_pre_auth_token()
    vulnerable = state["effective_mode"] == "vulnerable"
    if vulnerable:
        inspect_result = execute_vulnerable_inspect(token)
    else:
        inspect_result = execute_mitigated_inspect(token)

    run_result = "passed" if inspect_result.status_code == 200 else "blocked"
    run = record_lab_run("auth_session", run_result)

    evidence = {
        "action": "inspect_token",
        "effective_mode": state["effective_mode"],
        "token_inspected": token,
        "is_authenticated": inspect_result.is_authenticated,
        "user_email": inspect_result.user_email or "None",
        "status_code": inspect_result.status_code,
        "status_label": inspect_result.status_label,
        "message": inspect_result.message,
        "simulated_account_takeover": inspect_result.simulated_account_takeover,
        "run_result": run.result,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return _render_auth_session_page(
        module, state, evidence=evidence, status_code=inspect_result.status_code
    )


@bp.post("/auth-session/simulate-logout")
@login_required
def auth_session_simulate_logout():
    """Simulate logging out the synthetic consultant."""
    module = get_vulnerability("auth_session")
    state = get_module_state("auth_session")
    form = AuthSessionSimulateLogoutForm()
    if not form.validate_on_submit():
        abort(400)

    active_session = get_active_session()
    token = active_session.token if active_session else get_pre_auth_token()
    vulnerable = state["effective_mode"] == "vulnerable"
    if vulnerable:
        logout_result = execute_vulnerable_logout(token)
    else:
        logout_result = execute_mitigated_logout(token)

    run = record_lab_run("auth_session", "passed")
    evidence = {
        "action": "simulate_logout",
        "effective_mode": state["effective_mode"],
        "logged_out_token": logout_result.token,
        "server_invalidated": logout_result.server_invalidated,
        "message": logout_result.message,
        "classification": logout_result.classification,
        "run_result": run.result,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return _render_auth_session_page(module, state, evidence=evidence)


@bp.post("/auth-session/replay-token")
@login_required
def auth_session_replay_token():
    """Test replaying a previously used or discarded session token."""
    module = get_vulnerability("auth_session")
    state = get_module_state("auth_session")
    form = AuthSessionReplayTokenForm()
    if not form.validate_on_submit():
        abort(400)

    token = (form.token.data or "").strip()
    if not token:
        active = get_active_session()
        token = active.token if active else get_pre_auth_token()

    vulnerable = state["effective_mode"] == "vulnerable"
    if vulnerable:
        inspect_result = execute_vulnerable_inspect(token)
    else:
        inspect_result = execute_mitigated_inspect(token)

    run_result = "passed" if inspect_result.status_code == 200 else "blocked"
    run = record_lab_run("auth_session", run_result)

    evidence = {
        "action": "replay_token",
        "effective_mode": state["effective_mode"],
        "token_replayed": token,
        "is_authenticated": inspect_result.is_authenticated,
        "user_email": inspect_result.user_email or "None",
        "status_code": inspect_result.status_code,
        "status_label": inspect_result.status_label,
        "message": inspect_result.message,
        "simulated_account_takeover": inspect_result.simulated_account_takeover,
        "run_result": run.result,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return _render_auth_session_page(
        module, state, evidence=evidence, status_code=inspect_result.status_code
    )


@bp.post("/auth-session/reset")
@login_required
def auth_session_reset():
    """Reset the synthetic auth & session scenario store to clean initial state."""
    form = AuthSessionResetForm()
    if not form.validate_on_submit():
        abort(400)

    reset_auth_session_store()
    flash("Synthetic session scenario restored to initial unauthenticated state.", "info")
    return redirect(url_for("security_lab.auth_session_page"))


def _render_auth_session_page(
    module, state, evidence=None, active_token=None, status_code=200
):
    """Render the Auth & Session Security lab page and attach demonstration cookie."""
    snapshot = get_store_snapshot()
    login_form = AuthSessionSimulateLoginForm()
    inspect_form = AuthSessionInspectTokenForm()
    logout_form = AuthSessionSimulateLogoutForm()
    replay_form = AuthSessionReplayTokenForm()
    reset_form = AuthSessionResetForm()

    if not inspect_form.token.data:
        inspect_form.token.data = snapshot["pre_auth_token"]
    if not replay_form.token.data:
        active = snapshot.get("active_session")
        replay_form.token.data = active["token"] if active else snapshot["pre_auth_token"]

    vulnerable = state["effective_mode"] == "vulnerable"
    current_token = (
        active_token
        or (snapshot["active_session"]["token"] if snapshot.get("active_session") else snapshot["pre_auth_token"])
    )

    response = make_response(
        render_template(
            "security_lab/auth_session.html",
            module=module,
            state=state,
            snapshot=snapshot,
            login_form=login_form,
            inspect_form=inspect_form,
            logout_form=logout_form,
            replay_form=replay_form,
            reset_form=reset_form,
            evidence=evidence,
            current_token=current_token,
            cookie_name=AUTH_SESSION_COOKIE_NAME,
            consultant_name=LAB_AUTH_SESSION_USER_NAME,
            consultant_email=LAB_AUTH_SESSION_USER_EMAIL,
            contracts_summary=LAB_AUTH_SESSION_CONTRACT_SUMMARY,
        ),
        status_code,
    )

    # Attach the synthetic demonstration cookie ONLY to responses from this lab endpoint.
    # CRITICAL ISOLATION: This never alters or interferes with the real Flask session cookie ("session").
    if vulnerable:
        response.set_cookie(
            AUTH_SESSION_COOKIE_NAME,
            current_token,
            path="/security-lab/auth-session",
            httponly=False,
            samesite=None,
        )
    else:
        response.set_cookie(
            AUTH_SESSION_COOKIE_NAME,
            current_token,
            path="/security-lab/auth-session",
            httponly=True,
            samesite="Lax",
        )

    return response

