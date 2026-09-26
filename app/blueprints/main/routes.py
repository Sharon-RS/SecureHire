"""Landing page and authenticated dashboard."""

from flask import render_template
from flask_login import current_user, login_required

from ...repositories.marketplace import proposals_for_freelancer, search_open_gigs
from ...models import Gig, Proposal
from . import bp


@bp.get("/")
def index():
    gigs = search_open_gigs()[:6]
    return render_template("main/index.html", gigs=gigs)


@bp.get("/dashboard")
@login_required
def dashboard():
    if current_user.role == "buyer":
        gigs = (
            Gig.query.filter_by(owner_id=current_user.id)
            .order_by(Gig.created_at.desc())
            .limit(10)
            .all()
        )
        proposals = (
            Proposal.query.join(Gig)
            .filter(Gig.owner_id == current_user.id)
            .order_by(Proposal.created_at.desc())
            .limit(10)
            .all()
        )
        received_count = Proposal.query.join(Gig).filter(Gig.owner_id == current_user.id).count()
    elif current_user.role == "freelancer":
        gigs = []
        proposals = proposals_for_freelancer(current_user.id)
        received_count = 0
    else:
        gigs = []
        proposals = []
        received_count = 0
    return render_template(
        "main/dashboard.html",
        gigs=gigs,
        proposals=proposals[:10],
        received_count=received_count,
    )
