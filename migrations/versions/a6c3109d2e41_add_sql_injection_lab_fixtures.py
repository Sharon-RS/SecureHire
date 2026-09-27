"""Add dedicated synthetic SQL injection lab fixtures.

Revision ID: a6c3109d2e41
Revises: 5b2b99e598a8
Create Date: 2026-09-27
"""
from alembic import op
import sqlalchemy as sa


revision = "a6c3109d2e41"
down_revision = "5b2b99e598a8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "security_lab_gig_fixtures",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=140), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_lab_gig_fixtures_category",
        "security_lab_gig_fixtures",
        ["category"],
        unique=False,
    )
    fixtures = sa.table(
        "security_lab_gig_fixtures",
        sa.column("id", sa.Integer()),
        sa.column("title", sa.String(length=140)),
        sa.column("category", sa.String(length=80)),
        sa.column("description", sa.Text()),
    )
    op.bulk_insert(
        fixtures,
        [
            {
                "id": 1,
                "title": "Python",
                "category": "Development",
                "description": "A synthetic local fixture for a small Python automation task.",
            },
            {
                "id": 2,
                "title": "Automate weekly reports",
                "category": "Python",
                "description": "A synthetic local fixture for a report-generation script.",
            },
            {
                "id": 3,
                "title": "Brand icon refresh",
                "category": "Design",
                "description": "A synthetic local fixture for a simple visual identity update.",
            },
        ],
    )


def downgrade():
    op.drop_index(
        "ix_security_lab_gig_fixtures_category",
        table_name="security_lab_gig_fixtures",
    )
    op.drop_table("security_lab_gig_fixtures")
