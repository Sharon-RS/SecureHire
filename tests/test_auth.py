"""Authentication and profile workflow tests."""

from app.extensions import db
from app.models import User
from conftest import csrf_token, login_as, make_user, post_form


def test_registration_stores_hash_and_creates_profile(app, client):
    response = post_form(
        client,
        "/auth/register",
        "/auth/register",
        {
            "email": "New.Buyer@example.test",
            "role": "buyer",
            "password": "Synthetic-Password-2026!",
            "confirm_password": "Synthetic-Password-2026!",
        },
    )
    assert response.status_code == 302
    with app.app_context():
        user = User.query.filter_by(email="new.buyer@example.test").one()
        assert user.password_hash != "Synthetic-Password-2026!"
        assert user.check_password("Synthetic-Password-2026!")
        assert user.role == "buyer"
        assert user.profile.display_name == "new.buyer"


def test_registration_cannot_assign_admin_role(client):
    response = post_form(
        client,
        "/auth/register",
        "/auth/register",
        {
            "email": "attempt@example.test",
            "role": "admin",
            "password": "Synthetic-Password-2026!",
            "confirm_password": "Synthetic-Password-2026!",
        },
    )
    assert response.status_code == 200
    assert b"buyer" in response.data.lower() or b"freelancer" in response.data.lower()


def test_login_and_csrf_protected_logout(app, client):
    user_id = make_user(app, "buyer@example.test", "buyer")
    response = login_as(client, "buyer@example.test")
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 200
    session_cookie = next(
        value for value in response.headers.getlist("Set-Cookie") if value.startswith("session=")
    )
    assert "HttpOnly" in session_cookie
    assert "SameSite=Lax" in session_cookie

    logout_token = csrf_token(client, "/dashboard")
    response = client.post("/auth/logout", data={"csrf_token": logout_token})
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 302
    with app.app_context():
        assert db.session.get(User, user_id) is not None


def test_login_rejects_wrong_password(client, app):
    make_user(app, "buyer@example.test", "buyer")
    response = post_form(
        client,
        "/auth/login",
        "/auth/login",
        {"email": "buyer@example.test", "password": "wrong-password"},
    )
    assert response.status_code == 200
    assert b"Email or password was not recognized." in response.data
    assert client.get("/dashboard").status_code == 302


def test_profile_access_and_edits_are_bound_to_current_user(app, client):
    alice_id = make_user(app, "alice@example.test", "buyer", "Alice")
    bob_id = make_user(app, "bob@example.test", "freelancer", "Bob")

    assert client.get("/auth/profile").status_code == 302
    login_as(client, "alice@example.test")
    assert client.get("/auth/profile").status_code == 200
    public_profile = client.get(f"/auth/profiles/{bob_id}")
    assert public_profile.status_code == 200
    assert b"Bob" in public_profile.data

    response = post_form(
        client,
        "/auth/profile/edit",
        "/auth/profile/edit",
        {"display_name": "Alice Updated", "bio": "Synthetic profile.", "skills": "Research", "user_id": str(bob_id)},
    )
    assert response.status_code == 302
    assert client.post(f"/auth/profiles/{bob_id}/edit").status_code == 404
    with app.app_context():
        alice = db.session.get(User, alice_id)
        bob = db.session.get(User, bob_id)
        assert alice.profile.display_name == "Alice Updated"
        assert bob.profile.display_name == "Bob"


def test_missing_csrf_token_rejects_profile_change(app, client):
    make_user(app, "alice@example.test", "buyer", "Alice")
    login_as(client, "alice@example.test")
    response = client.post(
        "/auth/profile/edit",
        data={"display_name": "Changed", "bio": "", "skills": ""},
    )
    assert response.status_code == 400
