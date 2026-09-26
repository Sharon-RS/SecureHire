"""Authentication and account creation services."""

from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import Profile, User


class AccountExistsError(Exception):
    """Raised when an account email is already registered."""


def register_user(email: str, password: str, role: str) -> User:
    normalized_email = email.strip().lower()
    if role not in {"buyer", "freelancer"}:
        raise ValueError("Choose Buyer or Freelancer.")
    user = User(email=normalized_email, role=role, status="active", is_admin=False)
    user.set_password(password)
    user.profile = Profile(display_name=normalized_email.split("@", 1)[0][:100])
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise AccountExistsError from exc
    return user
