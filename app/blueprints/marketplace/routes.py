"""Gig and proposal workflows with server-side ownership checks."""

from decimal import Decimal

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ...extensions import db
from ...forms.marketplace import (
    CloseGigForm,
    GigForm,
    ProposalDecisionForm,
    ProposalForm,
)
from ...models import Gig, Proposal
from ...repositories.marketplace import (
    find_gig,
    find_proposal,
    proposals_for_gig,
    proposals_for_freelancer,
    search_open_gigs,
)
from ...services.authorization import roles_required
from ...services.marketplace import (
    MarketplaceError,
    change_proposal_status,
    close_gig,
    create_gig,
    submit_proposal,
)
from . import bp


def _get_gig_or_404(gig_id: int) -> Gig:
    gig = find_gig(gig_id)
    if not gig:
        abort(404)
    return gig


@bp.get("/gigs")
def browse_gigs():
    search = request.args.get("q", "", type=str)[:100].strip()
    gigs = search_open_gigs(search)
    return render_template("marketplace/gigs.html", gigs=gigs, search=search)


@bp.get("/gigs/<int:gig_id>")
def gig_detail(gig_id: int):
    gig = _get_gig_or_404(gig_id)
    proposal_form = ProposalForm()
    close_form = CloseGigForm()
    owner_view = current_user.is_authenticated and current_user.id == gig.owner_id
    already_applied = False
    if current_user.is_authenticated and current_user.role == "freelancer":
        already_applied = Proposal.query.filter_by(
            gig_id=gig.id, freelancer_id=current_user.id
        ).first() is not None
    return render_template(
        "marketplace/gig_detail.html",
        gig=gig,
        proposal_form=proposal_form,
        close_form=close_form,
        owner_view=owner_view,
        already_applied=already_applied,
    )


@bp.route("/gigs/new", methods=["GET", "POST"])
@login_required
@roles_required("buyer")
def create_gig_route():
    form = GigForm()
    if form.validate_on_submit():
        gig = create_gig(
            current_user.id,
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            budget=Decimal(str(form.budget.data)),
        )
        flash("Your gig is live.", "success")
        return redirect(url_for("marketplace.gig_detail", gig_id=gig.id))
    return render_template("marketplace/gig_form.html", form=form, page_title="Create a gig")


@bp.route("/gigs/<int:gig_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required("buyer")
def edit_gig(gig_id: int):
    gig = _get_gig_or_404(gig_id)
    if gig.owner_id != current_user.id:
        abort(404)
    if gig.status != "open":
        flash("Closed gigs cannot be edited.", "warning")
        return redirect(url_for("marketplace.gig_detail", gig_id=gig.id))
    form = GigForm(obj=gig)
    if form.validate_on_submit():
        gig.title = form.title.data.strip()
        gig.category = form.category.data.strip()
        gig.description = form.description.data.strip()
        gig.budget = Decimal(str(form.budget.data))
        db.session.commit()
        flash("Gig updated.", "success")
        return redirect(url_for("marketplace.gig_detail", gig_id=gig.id))
    return render_template("marketplace/gig_form.html", form=form, page_title="Edit your gig")


@bp.post("/gigs/<int:gig_id>/close")
@login_required
@roles_required("buyer")
def close_gig_route(gig_id: int):
    gig = _get_gig_or_404(gig_id)
    if gig.owner_id != current_user.id:
        abort(404)
    form = CloseGigForm()
    if form.validate_on_submit():
        try:
            close_gig(gig)
        except MarketplaceError as exc:
            flash(str(exc), "warning")
        else:
            flash("Gig closed. It is no longer accepting proposals.", "success")
    return redirect(url_for("marketplace.gig_detail", gig_id=gig.id))


@bp.route("/gigs/<int:gig_id>/proposals/new", methods=["GET", "POST"])
@login_required
@roles_required("freelancer")
def submit_proposal_route(gig_id: int):
    gig = _get_gig_or_404(gig_id)
    if gig.status != "open":
        abort(404)
    form = ProposalForm()
    if form.validate_on_submit():
        try:
            proposal = submit_proposal(
                gig,
                current_user.id,
                cover_letter=form.cover_letter.data,
                proposed_price=Decimal(str(form.proposed_price.data)),
                timeline=form.timeline.data,
            )
        except MarketplaceError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("marketplace.gig_detail", gig_id=gig.id))
        flash("Your proposal was sent to the gig owner.", "success")
        return redirect(url_for("marketplace.proposal_detail", proposal_id=proposal.id))
    return render_template("marketplace/proposal_form.html", form=form, gig=gig)


@bp.get("/gigs/<int:gig_id>/proposals")
@login_required
@roles_required("buyer")
def manage_proposals(gig_id: int):
    gig = _get_gig_or_404(gig_id)
    if gig.owner_id != current_user.id:
        abort(404)
    proposals = proposals_for_gig(gig.id)
    decision_forms = {proposal.id: ProposalDecisionForm() for proposal in proposals}
    return render_template(
        "marketplace/proposals.html", gig=gig, proposals=proposals, decision_forms=decision_forms
    )


@bp.route("/proposals/<int:proposal_id>", methods=["GET"])
@login_required
def proposal_detail(proposal_id: int):
    proposal = find_proposal(proposal_id)
    if not proposal:
        abort(404)
    if current_user.id not in {proposal.freelancer_id, proposal.gig.owner_id}:
        abort(404)
    decision_form = ProposalDecisionForm()
    return render_template(
        "marketplace/proposal_detail.html",
        proposal=proposal,
        decision_form=decision_form,
        owner_view=current_user.id == proposal.gig.owner_id,
    )


@bp.post("/proposals/<int:proposal_id>/decision")
@login_required
@roles_required("buyer")
def decide_proposal(proposal_id: int):
    proposal = find_proposal(proposal_id)
    if not proposal:
        abort(404)
    if proposal.gig.owner_id != current_user.id:
        abort(404)
    form = ProposalDecisionForm()
    if form.validate_on_submit():
        try:
            change_proposal_status(proposal, form.decision.data)
        except MarketplaceError as exc:
            db.session.rollback()
            flash(str(exc), "warning")
        else:
            flash(f"Proposal {form.decision.data}.", "success")
    else:
        flash("Choose a valid decision.", "warning")
    return redirect(url_for("marketplace.manage_proposals", gig_id=proposal.gig_id))
