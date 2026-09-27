"""Add marketplace reviews and Stored XSS lab fixture storage.

Revision ID: b72f03d9a416
Revises: a6c3109d2e41
Create Date: 2026-09-27
"""
from alembic import op
import sqlalchemy as sa


revision = "b72f03d9a416"
down_revision = "a6c3109d2e41"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "reviews",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("proposal_id", sa.Integer(), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), nullable=False),
        sa.Column("reviewee_id", sa.Integer(), nullable=False),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint("rating >= 1 AND rating <= 5", name="ck_reviews_rating_range"),
        sa.ForeignKeyConstraint(
            ["proposal_id"], ["proposals.id"], name="fk_reviews_proposal", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["reviewer_id"], ["users.id"], name="fk_reviews_reviewer", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["reviewee_id"], ["users.id"], name="fk_reviews_reviewee", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("proposal_id", "reviewer_id", name="uq_reviews_proposal_reviewer"),
    )
    op.create_index(
        "ix_reviews_reviewee_created",
        "reviews",
        ["reviewee_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "stored_xss_demo_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("payload", sa.String(length=200), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_stored_xss_demo_user", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", name="uq_stored_xss_demo_user"),
    )


def downgrade():
    op.drop_table("stored_xss_demo_entries")
    op.drop_index("ix_reviews_reviewee_created", table_name="reviews")
    op.drop_table("reviews")
