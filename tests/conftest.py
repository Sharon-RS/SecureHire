"""Isolated test fixtures and helpers."""

import re

import pytest

from app import create_app
from app.extensions import db
from app.models import Profile, User


@pytest.fixture
def app():
    application = create_app(
        "testing",
        {
            "SQLALCHEMY_DATABASE_URI": "sqlite+pysqlite:///:memory:",
            "WTF_CSRF_ENABLED": True,
            "TESTING": True,
            "ENFORCE_LOOPBACK": True,
        },
    )
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def csrf_token(client, path):
    response = client.get(path)
    assert response.status_code == 200, response.status_code
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.get_data(as_text=True))
    assert match, "Expected a CSRF token in the form"
    return match.group(1)


def post_form(client, form_page, action, data):
    payload = dict(data)
    payload["csrf_token"] = csrf_token(client, form_page)
    return client.post(action, data=payload)


def make_user(app, email, role, display_name=None, password="SecureHire-Test-Password!"):
    with app.app_context():
        user = User(
            email=email.lower(),
            role=role,
            status="active",
            is_admin=(role == "admin"),
        )
        user.set_password(password)
        user.profile = Profile(display_name=display_name or email.split("@", 1)[0])
        db.session.add(user)
        db.session.commit()
        return user.id


def login_as(client, email, password="SecureHire-Test-Password!"):
    return post_form(
        client,
        "/auth/login",
        "/auth/login",
        {"email": email, "password": password},
    )
