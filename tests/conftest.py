"""Pytest fixtures for PhishSim unit and integration tests."""
try:
    import pytest
except ImportError:
    pytest = None  # type: ignore

from app import create_app
from app.extensions import db
from app.models import User
from app.security import login_limiter


def make_test_app():
    """Create an isolated in-memory SQLite Flask app for testing."""
    login_limiter.clear_all()
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test-secret-key-at-least-16-chars",
            "ADMIN_EMAIL": "admin@example.com",
            "ADMIN_PASSWORD": "AdminTestPassword123!",
            "CSRF_ENABLED": True,
            "LOGIN_RATE_LIMIT": 3,
            "LOGIN_RATE_WINDOW": 60,
            "ENTRA_CLIENT_ID": "test-entra-client-id",
            "ENTRA_CLIENT_SECRET": "test-entra-secret",
            "REPEAT_OFFENDER_DAYS": 14,
        }
    )
    return app


if pytest is not None:
    @pytest.fixture()
    def app():
        test_app = make_test_app()
        yield test_app
        with test_app.app_context():
            db.session.remove()
            db.drop_all()

    @pytest.fixture()
    def client(app):
        return app.test_client()

    @pytest.fixture()
    def admin_client(app, client):
        with app.app_context():
            admin = User.query.filter_by(email="admin@example.com").first()
            admin_id = str(admin.id)
        with client.session_transaction() as sess:
            sess["_user_id"] = admin_id
            sess["_csrf_token"] = "valid-test-csrf-token"
        return client
