"""Marketplace authorization and workflow tests."""

from decimal import Decimal

from app.extensions import db
from app.models import Gig, Proposal
from conftest import login_as, make_user, post_form


GIG_DATA = {
    "title": "Create a visual identity",
    "category": "Design",
    "description": "Create a considered visual identity for a synthetic local business.",
    "budget": "850.00",
}
PROPOSAL_DATA = {
    "cover_letter": "I would begin with discovery, then present two focused design directions.",
    "proposed_price": "700.00",
    "timeline": "Two weeks",
}


def make_gig(app, owner_id, title="Create a visual identity", description=None):
    with app.app_context():
        gig = Gig(
            owner_id=owner_id,
            title=title,
            description=description or "A synthetic project description for a local test gig.",
            category="Design",
            budget=Decimal("850.00"),
            status="open",
        )
        db.session.add(gig)
        db.session.commit()
        return gig.id


def make_proposal(app, gig_id, freelancer_id):
    with app.app_context():
        proposal = Proposal(
            gig_id=gig_id,
            freelancer_id=freelancer_id,
            cover_letter="A synthetic proposal with a clear approach for this project.",
            proposed_price=Decimal("700.00"),
            timeline="Two weeks",
            status="pending",
        )
        db.session.add(proposal)
        db.session.commit()
        return proposal.id


def test_buyer_can_create_gig_but_freelancer_cannot(app, client):
    buyer_id = make_user(app, "buyer@example.test", "buyer")
    login_as(client, "buyer@example.test")
    response = post_form(client, "/gigs/new", "/gigs/new", GIG_DATA)
    assert response.status_code == 302
    with app.app_context():
        gig = Gig.query.filter_by(owner_id=buyer_id).one()
        assert gig.title == GIG_DATA["title"]
        assert gig.status == "open"

    freelancer_client = app.test_client()
    make_user(app, "freelancer@example.test", "freelancer")
    login_as(freelancer_client, "freelancer@example.test")
    assert freelancer_client.get("/gigs/new").status_code == 403


def test_gig_editing_is_owner_only(app, client):
    owner_id = make_user(app, "owner@example.test", "buyer")
    make_user(app, "other@example.test", "buyer")
    gig_id = make_gig(app, owner_id)

    login_as(client, "owner@example.test")
    response = post_form(
        client,
        f"/gigs/{gig_id}/edit",
        f"/gigs/{gig_id}/edit",
        {**GIG_DATA, "title": "Updated visual identity"},
    )
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Gig, gig_id).title == "Updated visual identity"

    other = app.test_client()
    login_as(other, "other@example.test")
    assert other.get(f"/gigs/{gig_id}/edit").status_code == 404
    denied = post_form(
        other,
        "/auth/profile/edit",
        f"/gigs/{gig_id}/edit",
        {**GIG_DATA, "title": "Stolen edit"},
    )
    assert denied.status_code == 404
    with app.app_context():
        assert db.session.get(Gig, gig_id).title == "Updated visual identity"


def test_gig_closing_is_owner_only(app, client):
    owner_id = make_user(app, "owner@example.test", "buyer")
    make_user(app, "other@example.test", "buyer")
    gig_id = make_gig(app, owner_id)

    login_as(client, "owner@example.test")
    response = post_form(client, f"/gigs/{gig_id}", f"/gigs/{gig_id}/close", {})
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Gig, gig_id).status == "closed"

    other = app.test_client()
    login_as(other, "other@example.test")
    denied = post_form(other, "/auth/profile/edit", f"/gigs/{gig_id}/close", {})
    assert denied.status_code == 404
    with app.app_context():
        assert db.session.get(Gig, gig_id).status == "closed"


def test_gig_search_returns_matching_open_gigs(app, client):
    owner_id = make_user(app, "owner@example.test", "buyer")
    make_gig(app, owner_id, title="Accessible garden planning")
    make_gig(app, owner_id, title="Audio editing project")
    response = client.get("/gigs?q=garden")
    assert response.status_code == 200
    assert b"Accessible garden planning" in response.data
    assert b"Audio editing project" not in response.data
    escaped_wildcard = client.get("/gigs?q=%25")
    assert escaped_wildcard.status_code == 200
    assert b"Accessible garden planning" not in escaped_wildcard.data


def test_freelancer_can_submit_one_proposal_per_gig(app, client):
    owner_id = make_user(app, "owner@example.test", "buyer")
    freelancer_id = make_user(app, "freelancer@example.test", "freelancer")
    gig_id = make_gig(app, owner_id)
    login_as(client, "freelancer@example.test")

    response = post_form(
        client,
        f"/gigs/{gig_id}/proposals/new",
        f"/gigs/{gig_id}/proposals/new",
        PROPOSAL_DATA,
    )
    assert response.status_code == 302
    duplicate = post_form(
        client,
        f"/gigs/{gig_id}/proposals/new",
        f"/gigs/{gig_id}/proposals/new",
        PROPOSAL_DATA,
    )
    assert duplicate.status_code == 302
    with app.app_context():
        assert Proposal.query.filter_by(gig_id=gig_id, freelancer_id=freelancer_id).count() == 1

    buyer_client = app.test_client()
    login_as(buyer_client, "owner@example.test")
    assert buyer_client.get(f"/gigs/{gig_id}/proposals/new").status_code == 403


def test_proposal_is_visible_only_to_submitter_and_gig_owner(app):
    owner_email = "owner@example.test"
    freelancer_email = "freelancer@example.test"
    owner_id = make_user(app, owner_email, "buyer")
    freelancer_id = make_user(app, freelancer_email, "freelancer")
    make_user(app, "outsider@example.test", "freelancer")
    gig_id = make_gig(app, owner_id)
    proposal_id = make_proposal(app, gig_id, freelancer_id)

    freelancer = app.test_client()
    login_as(freelancer, freelancer_email)
    assert freelancer.get(f"/proposals/{proposal_id}").status_code == 200

    owner = app.test_client()
    login_as(owner, owner_email)
    assert owner.get(f"/proposals/{proposal_id}").status_code == 200
    assert owner.get(f"/gigs/{gig_id}/proposals").status_code == 200

    outsider = app.test_client()
    login_as(outsider, "outsider@example.test")
    assert outsider.get(f"/proposals/{proposal_id}").status_code == 404
    assert outsider.get(f"/gigs/{gig_id}/proposals").status_code == 403


def test_only_gig_owner_can_accept_or_reject_proposal(app):
    owner_email = "owner@example.test"
    owner_id = make_user(app, owner_email, "buyer")
    make_user(app, "other-buyer@example.test", "buyer")
    gig_id = make_gig(app, owner_id)
    applicant_id = make_user(app, "applicant@example.test", "freelancer")
    proposal_id = make_proposal(app, gig_id, applicant_id)

    other = app.test_client()
    login_as(other, "other-buyer@example.test")
    denied = post_form(
        other,
        "/auth/profile/edit",
        f"/proposals/{proposal_id}/decision",
        {"decision": "accepted"},
    )
    assert denied.status_code == 404

    owner = app.test_client()
    login_as(owner, owner_email)
    response = post_form(
        owner,
        f"/gigs/{gig_id}/proposals",
        f"/proposals/{proposal_id}/decision",
        {"decision": "accepted"},
    )
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Proposal, proposal_id).status == "accepted"


def test_closed_gig_does_not_accept_new_proposals(app, client):
    owner_id = make_user(app, "owner@example.test", "buyer")
    make_user(app, "freelancer@example.test", "freelancer")
    gig_id = make_gig(app, owner_id)
    with app.app_context():
        gig = db.session.get(Gig, gig_id)
        gig.status = "closed"
        db.session.commit()

    login_as(client, "freelancer@example.test")
    assert client.get(f"/gigs/{gig_id}/proposals/new").status_code == 404



def test_a_gig_cannot_accept_multiple_proposals(app):
    owner_email = "owner@example.test"
    owner_id = make_user(app, owner_email, "buyer")
    gig_id = make_gig(app, owner_id)
    first_freelancer_id = make_user(app, "first@example.test", "freelancer")
    second_freelancer_id = make_user(app, "second@example.test", "freelancer")
    first_proposal_id = make_proposal(app, gig_id, first_freelancer_id)
    second_proposal_id = make_proposal(app, gig_id, second_freelancer_id)

    owner = app.test_client()
    login_as(owner, owner_email)
    first = post_form(
        owner,
        f"/gigs/{gig_id}/proposals",
        f"/proposals/{first_proposal_id}/decision",
        {"decision": "accepted"},
    )
    assert first.status_code == 302
    second = post_form(
        owner,
        f"/gigs/{gig_id}/proposals",
        f"/proposals/{second_proposal_id}/decision",
        {"decision": "accepted"},
    )
    assert second.status_code == 302
    with app.app_context():
        assert db.session.get(Proposal, first_proposal_id).status == "accepted"
        assert db.session.get(Proposal, second_proposal_id).status == "pending"
