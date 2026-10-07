"""Application configuration.

All settings are read from environment variables (loaded from a .env file in
development). Copy .env.example to .env and edit the values there.
"""
a=1
import os
from dotenv import load_dotenv

load_dotenv()


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    # Environment ("development" or "production")
    ENV = os.getenv("FLASK_ENV", "development").strip().lower()

    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = _bool(
        os.getenv("SESSION_COOKIE_SECURE"), default=(ENV == "production")
    )

    # CSRF & Reverse Proxy
    CSRF_ENABLED = _bool(os.getenv("CSRF_ENABLED"), True)
    TRUST_PROXY_HEADERS = _bool(os.getenv("TRUST_PROXY_HEADERS"), True)

    # Login brute-force protection (max attempts per window in seconds)
    LOGIN_RATE_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT", "5"))
    LOGIN_RATE_WINDOW = int(os.getenv("LOGIN_RATE_WINDOW", "60"))

    # Enterprise SSO (Microsoft Entra ID, Google Workspace, Okta)
    SSO_AUTO_PROVISION = _bool(os.getenv("SSO_AUTO_PROVISION"), True)
    SSO_DEFAULT_ROLE = os.getenv("SSO_DEFAULT_ROLE", "viewer").strip().lower()

    ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "").strip()
    ENTRA_CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "").strip()
    ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID", "common").strip()

    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()

    OKTA_CLIENT_ID = os.getenv("OKTA_CLIENT_ID", "").strip()
    OKTA_CLIENT_SECRET = os.getenv("OKTA_CLIENT_SECRET", "").strip()
    OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "").strip()

    # Database. Default is a local SQLite file; swap for MySQL in production, e.g.
    #   DATABASE_URL=mysql+pymysql://user:pass@localhost/phishsim
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///phishsim.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Public base URL used to build tracking links inside emails.
    BASE_URL = os.getenv("BASE_URL", "http://localhost:5000")

    # Fallback / initial default SMTP settings (seeded into SMTPProfile on first boot).
    SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS = _bool(os.getenv("SMTP_USE_TLS"), False)

    # First admin account, created automatically on first run.
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

    # Repeat-offender follow-up threshold in days
    REPEAT_OFFENDER_DAYS = int(os.getenv("REPEAT_OFFENDER_DAYS", "14"))

    # Optional Slack / generic webhook URL for security & campaign alerts
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "").strip()


_INSECURE_SECRETS = {
    "dev-secret-change-me",
    "change-this-to-a-long-random-string",
    "",
}
_INSECURE_PASSWORDS = {"admin123", "password", "123456", ""}


def validate_production_config(app) -> None:
    """Fail fast in production if default secrets are still in use, or warn in dev."""
    env = (app.config.get("ENV") or "development").lower()
    secret = app.config.get("SECRET_KEY") or ""
    admin_pw = app.config.get("ADMIN_PASSWORD") or ""

    issues = []
    if secret in _INSECURE_SECRETS or len(secret) < 16:
        issues.append("SECRET_KEY is set to a default or short value (<16 chars)")
    if admin_pw in _INSECURE_PASSWORDS:
        issues.append("ADMIN_PASSWORD is set to the default value")

    if not issues:
        return

    msg = "Security configuration check: " + "; ".join(issues)
    if env == "production":
        raise RuntimeError(
            f"Refusing to start in production mode: {msg}. "
            "Update your .env or environment variables before deploying."
        )
    app.logger.warning("%s (allowed in %s mode)", msg, env)
