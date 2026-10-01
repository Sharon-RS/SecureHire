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
    ReviewForm,
)
from ...models import Gig, Proposal
from ...repositories.marketplace import (
    distinct_open_categories,
    find_gig,
    find_proposal,
    find_review_for_reviewer,
    proposals_for_gig,
    reviews_for_gig,
)
from ...services.authorization import roles_required
from ...services.marketplace import (
    MarketplaceError,
    MarketplaceFilterCriteria,
    change_proposal_status,
    close_gig,
    create_gig,
    filter_open_gigs,
    submit_proposal,
    submit_review,
)
from . import bp


def _get_gig_or_404(gig_id: int) -> Gig:
    gig = find_gig(gig_id)
    if not gig:
        abort(404)
    return gig


@bp.get("/gigs")
def browse_gigs():
    criteria = MarketplaceFilterCriteria.from_params(
        query=request.args.get("q"),
        category=request.args.get("category"),
        max_budget_raw=request.args.get("max_budget"),
    )
    gigs = filter_open_gigs(criteria)
    categories = distinct_open_categories()
    raw_max_budget = (request.args.get("max_budget") or "").strip()
    return render_template(
        "marketplace/gigs.html",
        gigs=gigs,
        search=criteria.query,
        selected_category=criteria.category,
        max_budget=str(criteria.max_budget) if criteria.max_budget is not None else raw_max_budget,
        categories=categories,
    )


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
        reviews=reviews_for_gig(gig.id),
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
    my_review = find_review_for_reviewer(proposal.id, current_user.id)
    return render_template(
        "marketplace/proposal_detail.html",
        proposal=proposal,
        decision_form=decision_form,
        owner_view=current_user.id == proposal.gig.owner_id,
        my_review=my_review,
    )


@bp.route("/proposals/<int:proposal_id>/review", methods=["GET", "POST"])
@login_required
def write_review(proposal_id: int):
    """Allow either participant to review the other after an accepted proposal."""
    proposal = find_proposal(proposal_id)
    if proposal is None:
        abort(404)
    if current_user.id not in {proposal.freelancer_id, proposal.gig.owner_id}:
        abort(404)
    if proposal.status != "accepted":
        abort(409)

    existing_review = find_review_for_reviewer(proposal.id, current_user.id)
    if existing_review is not None:
        flash("You have already reviewed this interaction.", "info")
        return redirect(url_for("marketplace.proposal_detail", proposal_id=proposal.id))

    reviewee = (
        proposal.freelancer
        if current_user.id == proposal.gig.owner_id
        else proposal.gig.owner
    )
    form = ReviewForm()
    if form.validate_on_submit():
        try:
            submit_review(
                proposal.id,
                current_user.id,
                rating=form.rating.data,
                body=form.body.data,
            )
        except MarketplaceError as exc:
            db.session.rollback()
            flash(str(exc), "warning")
        else:
            flash("Your review was published.", "success")
            return redirect(url_for("marketplace.gig_detail", gig_id=proposal.gig_id))

    return render_template(
        "marketplace/review_form.html",
        form=form,
        proposal=proposal,
        reviewee=reviewee,
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
