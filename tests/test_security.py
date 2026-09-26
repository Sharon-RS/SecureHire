"""Local access and normal security-control tests."""

from conftest import make_user, login_as, post_form


def test_loopback_gate_ignores_forwarded_headers(client):
    response = client.get(
        "/",
        environ_overrides={"REMOTE_ADDR": "198.51.100.22"},
        headers={"X-Forwarded-For": "127.0.0.1"},
    )
    assert response.status_code == 403


def test_loopback_gate_rejects_unapproved_host(client):
    response = client.get("/", headers={"Host": "marketplace.example.test"})
    assert response.status_code == 400


def test_loopback_host_is_allowed_and_secure_headers_are_present(client):
    response = client.get("/", headers={"Host": "localhost"})
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_csrf_is_required_for_normal_marketplace_posts(app):
    user_id = make_user(app, "freelancer@example.test", "freelancer")
    client = app.test_client()
    login_as(client, "freelancer@example.test")
    response = client.post(
        "/gigs/new",
        data={
            "title": "A secure listing title",
            "category": "Design",
            "description": "A sufficiently detailed synthetic gig description for testing.",
            "budget": "100.00",
        },
    )
    assert response.status_code == 400
