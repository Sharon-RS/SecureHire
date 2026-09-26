"""User repository helpers."""

from ..models import User


def find_user_by_email(email: str) -> User | None:
    return User.query.filter_by(email=email.strip().lower()).first()
