"""Application data models."""

from flask_login import UserMixin
from sqlalchemy import CheckConstraint, UniqueConstraint, func

from ..extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('buyer', 'freelancer', 'admin')", name="ck_users_role"),
        CheckConstraint("status IN ('active', 'disabled')", name="ck_users_status"),
        db.Index("ix_users_role_status", "role", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="buyer")
    status = db.Column(db.String(20), nullable=False, default="active")
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    profile = db.relationship(
        "Profile", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    gigs = db.relationship("Gig", back_populates="owner", cascade="all, delete-orphan")
    proposals = db.relationship(
        "Proposal", back_populates="freelancer", cascade="all, delete-orphan"
    )
    security_modes_updated = db.relationship(
        "SecurityMode", back_populates="updated_by_user", foreign_keys="SecurityMode.updated_by"
    )
    security_mode_audits = db.relationship(
        "SecurityAuditLog", back_populates="changed_by_user", foreign_keys="SecurityAuditLog.changed_by"
    )


    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def display_role(self) -> str:
        return self.role.title()

    def set_password(self, password: str) -> None:
        from werkzeug.security import generate_password_hash

        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        from werkzeug.security import check_password_hash

        return check_password_hash(self.password_hash, password)


class Profile(db.Model):
    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    display_name = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text, nullable=False, default="")
    skills = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    user = db.relationship("User", back_populates="profile")


class Gig(db.Model):
    __tablename__ = "gigs"
    __table_args__ = (
        CheckConstraint("budget >= 0", name="ck_gigs_budget_nonnegative"),
        CheckConstraint("status IN ('open', 'closed')", name="ck_gigs_status"),
        db.Index("ix_gigs_status_created", "status", "created_at"),
        db.Index("ix_gigs_owner_status", "owner_id", "status"),
        db.Index("ix_gigs_category_status", "category", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = db.Column(db.String(140), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(80), nullable=False)
    budget = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    owner = db.relationship("User", back_populates="gigs")
    proposals = db.relationship("Proposal", back_populates="gig", cascade="all, delete-orphan")


class Proposal(db.Model):
    __tablename__ = "proposals"
    __table_args__ = (
        UniqueConstraint("gig_id", "freelancer_id", name="uq_proposals_gig_freelancer"),
        CheckConstraint("proposed_price >= 0", name="ck_proposals_price_nonnegative"),
        CheckConstraint(
            "status IN ('pending', 'accepted', 'rejected')", name="ck_proposals_status"
        ),
        db.Index("ix_proposals_gig_status", "gig_id", "status"),
        db.Index("ix_proposals_freelancer_status", "freelancer_id", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    gig_id = db.Column(db.Integer, db.ForeignKey("gigs.id", ondelete="CASCADE"), nullable=False)
    freelancer_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    cover_letter = db.Column(db.Text, nullable=False)
    proposed_price = db.Column(db.Numeric(10, 2), nullable=False)
    timeline = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    gig = db.relationship("Gig", back_populates="proposals")
    freelancer = db.relationship("User", back_populates="proposals")


class SecurityMode(db.Model):
    """Persisted administrator-selected setting for one allowlisted module."""

    __tablename__ = "security_modes"
    __table_args__ = (
        CheckConstraint(
            "vulnerability_key IN ('sqli', 'stored_xss', 'reflected_xss', 'idor_bola', "
            "'csrf', 'file_upload', 'path_traversal', 'clickjacking', 'auth_session', "
            "'security_misconfiguration')",
            name="ck_security_modes_vulnerability_key",
        ),
        CheckConstraint("mode IN ('vulnerable', 'mitigated')", name="ck_security_modes_mode"),
        UniqueConstraint("vulnerability_key", name="uq_security_modes_vulnerability_key"),
        db.Index("ix_security_modes_updated_by", "updated_by"),
    )

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_key = db.Column(db.String(64), nullable=False)
    mode = db.Column(
        db.String(16), nullable=False, default="mitigated", server_default="mitigated"
    )
    updated_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL", name="fk_security_modes_updated_by"),
        nullable=True,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    updated_by_user = db.relationship(
        "User", back_populates="security_modes_updated", foreign_keys=[updated_by]
    )
    audit_entries = db.relationship("SecurityAuditLog", back_populates="security_mode")
    lab_runs = db.relationship("LabRun", back_populates="security_mode")


class SecurityAuditLog(db.Model):
    """Append-only record of administrator mode changes."""

    __tablename__ = "security_audit_log"
    __table_args__ = (
        CheckConstraint(
            "previous_mode IN ('vulnerable', 'mitigated')",
            name="ck_security_audit_previous_mode",
        ),
        CheckConstraint(
            "new_mode IN ('vulnerable', 'mitigated')",
            name="ck_security_audit_new_mode",
        ),
        db.Index("ix_security_audit_key_changed_at", "vulnerability_key", "changed_at"),
        db.Index("ix_security_audit_changed_by", "changed_by"),
    )

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_key = db.Column(
        db.String(64),
        db.ForeignKey(
            "security_modes.vulnerability_key",
            ondelete="RESTRICT",
            name="fk_security_audit_vulnerability_key",
        ),
        nullable=False,
    )
    previous_mode = db.Column(db.String(16), nullable=False)
    new_mode = db.Column(db.String(16), nullable=False)
    changed_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="RESTRICT", name="fk_security_audit_changed_by"),
        nullable=False,
    )
    changed_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=func.now())

    security_mode = db.relationship("SecurityMode", back_populates="audit_entries")
    changed_by_user = db.relationship(
        "User", back_populates="security_mode_audits", foreign_keys=[changed_by]
    )


class LabRun(db.Model):
    """Bounded run status metadata; deliberately has no payload or request-body column."""

    __tablename__ = "lab_runs"
    __table_args__ = (
        CheckConstraint("mode IN ('vulnerable', 'mitigated')", name="ck_lab_runs_mode"),
        CheckConstraint(
            "result IN ('not_implemented', 'passed', 'blocked', 'failed')",
            name="ck_lab_runs_result",
        ),
        db.Index("ix_lab_runs_key_created_at", "vulnerability_key", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    vulnerability_key = db.Column(
        db.String(64),
        db.ForeignKey(
            "security_modes.vulnerability_key",
            ondelete="RESTRICT",
            name="fk_lab_runs_vulnerability_key",
        ),
        nullable=False,
    )
    mode = db.Column(db.String(16), nullable=False)
    result = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, server_default=func.now())

    security_mode = db.relationship("SecurityMode", back_populates="lab_runs")
