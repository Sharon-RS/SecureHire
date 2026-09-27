"""Idempotently seed synthetic local demonstration accounts and marketplace records."""

import os
import sys
from decimal import Decimal

from dotenv import load_dotenv

load_dotenv()

from app import create_app
from app.extensions import db
from app.models import Gig, Profile, Proposal, User
from app.services.demos.idor_bola import (
    LAB_FREELANCER_A_EMAIL,
    LAB_FREELANCER_B_EMAIL,
    LAB_SCENARIO_CATEGORY,
    LAB_SCENARIO_TITLE,
)


DEMO_ACCOUNTS = (
    ("admin@example.test", "admin", "SecureHire Admin"),
    ("buyer@example.test", "buyer", "Sample Buyer"),
    ("freelancer@example.test", "freelancer", "Sample Freelancer"),
    ("lab-freelancer-b@example.test", "freelancer", "Lab Freelancer B"),
)


def ensure_idor_scenario(buyer, freelancer_a, freelancer_b):
    """Seed the two closed-gig proposal records used only by the IDOR/BOLA lab."""
    gig = (
        Gig.query.filter_by(
            owner_id=buyer.id,
            title=LAB_SCENARIO_TITLE,
            category=LAB_SCENARIO_CATEGORY,
            status="closed",
        )
        .order_by(Gig.id.asc())
        .first()
    )
    if gig is None:
        gig = Gig(
            owner=buyer,
            title=LAB_SCENARIO_TITLE,
            description="A closed, synthetic proposal scenario reserved for the local Security Lab.",
            category=LAB_SCENARIO_CATEGORY,
            budget=Decimal("1000.00"),
            status="closed",
        )
        db.session.add(gig)
        db.session.flush()

    for freelancer, cover_letter, price, timeline in (
        (
            freelancer_a,
            "Synthetic proposal A: I would prepare a short discovery outline for the fixture project.",
            Decimal("725.00"),
            "Ten synthetic workdays",
        ),
        (
            freelancer_b,
            "Synthetic proposal B: I would provide a compact research and delivery plan for the fixture project.",
            Decimal("810.00"),
            "Twelve synthetic workdays",
        ),
    ):
        proposal = Proposal.query.filter_by(
            gig_id=gig.id,
            freelancer_id=freelancer.id,
        ).first()
        if proposal is None:
            db.session.add(
                Proposal(
                    gig=gig,
                    freelancer=freelancer,
                    cover_letter=cover_letter,
                    proposed_price=price,
                    timeline=timeline,
                    status="pending",
                )
            )


def main() -> int:
    password = os.getenv("SECUREHIRE_DEMO_PASSWORD", "")
    if len(password) < 12:
        print("Set SECUREHIRE_DEMO_PASSWORD in local .env to a synthetic value of at least 12 characters.")
        return 2

    app = create_app("development")
    with app.app_context():
        if app.config.get("APP_ENV") == "production":
            raise RuntimeError("Demo seeding is disabled in production.")
        accounts = {}
        for email, role, display_name in DEMO_ACCOUNTS:
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User(
                    email=email,
                    role=role,
                    status="active",
                    is_admin=(role == "admin"),
                )
                user.set_password(password)
                user.profile = Profile(display_name=display_name)
                db.session.add(user)
                db.session.flush()
            elif user.role != role or user.status != "active":
                raise RuntimeError(f"Existing synthetic account has unexpected state: {email}")
            elif user.profile is None:
                user.profile = Profile(display_name=display_name)
            accounts[email] = user

        freelancer = accounts[LAB_FREELANCER_A_EMAIL]
        lab_freelancer_b = accounts[LAB_FREELANCER_B_EMAIL]
        buyer = accounts["buyer@example.test"]
        gig = Gig.query.filter_by(owner_id=buyer.id, title="Design a community garden identity").first()
        if gig is None:
            gig = Gig(
                owner=buyer,
                title="Design a community garden identity",
                description=(
                    "Create a friendly visual identity for a fictional neighborhood garden. "
                    "Deliver a small logo set, a color palette, and a one-page usage guide."
                ),
                category="Design",
                budget=Decimal("650.00"),
                status="open",
            )
            db.session.add(gig)
            db.session.flush()

        proposal = Proposal.query.filter_by(gig_id=gig.id, freelancer_id=freelancer.id).first()
        if proposal is None:
            proposal = Proposal(
                gig=gig,
                freelancer=freelancer,
                cover_letter=(
                    "I would begin with a short discovery conversation, then share two visual "
                    "directions and refine the selected concept."
                ),
                proposed_price=Decimal("575.00"),
                timeline="About two weeks",
                status="pending",
            )
            db.session.add(proposal)

        ensure_idor_scenario(buyer, freelancer, lab_freelancer_b)

        db.session.commit()
        print("Synthetic demo accounts and sample marketplace records are ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
