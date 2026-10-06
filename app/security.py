"""Security helpers: RBAC, CSRF protection, rate limiting, TOTP 2FA, and Enterprise SSO."""
import base64
from collections import defaultdict
from functools import wraps
import hashlib
import hmac
import io
import secrets
import struct
import time
import urllib.parse

from flask import abort, current_app, redirect, request, session, url_for
from flask_login import current_user

try:
    import pyotp  # type: ignore
except ImportError:
    pyotp = None

try:
    from authlib.integrations.flask_client import OAuth  # type: ignore
except ImportError:
    OAuth = None


def admin_required(view):
    """Allow only users with role=='admin'; viewers get 403 Forbidden."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Synchronizer Token CSRF Protection
# ---------------------------------------------------------------------------
_CSRF_EXEMPT_VIEWS: set[str] = set()


def csrf_exempt(view):
    """Mark a view function as exempt from CSRF validation (e.g. target landing POST)."""
    _CSRF_EXEMPT_VIEWS.add(f"{view.__module__}.{view.__qualname__}")
    return view


def generate_csrf_token() -> str:
    """Return the session's CSRF token, creating one if needed."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(24)
    return session["_csrf_token"]


def init_security(app) -> None:
    """Register CSRF enforcement and security headers on the Flask app."""
    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    @app.before_request
    def _check_csrf():
        if not app.config.get("CSRF_ENABLED", True):
            return
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        if not request.endpoint:
            return
        view = app.view_functions.get(request.endpoint)
        if view is not None:
            qual = f"{view.__module__}.{view.__qualname__}"
            if qual in _CSRF_EXEMPT_VIEWS:
                return

        expected = session.get("_csrf_token")
        submitted = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
            or ""
        )
        if not expected or not secrets.compare_digest(str(expected), str(submitted)):
            abort(400, description="Invalid or missing CSRF token.")

    @app.after_request
    def _set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response


# ---------------------------------------------------------------------------
# In-memory Login Rate Limiter (Brute-force protection)
# ---------------------------------------------------------------------------
class LoginRateLimiter:
    """Track failed login attempts per IP over a sliding time window."""

    def __init__(self):
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_attempts: int = 5, window_seconds: int = 60) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        history = [t for t in self._attempts[key] if t > cutoff]
        self._attempts[key] = history
        if len(history) >= max_attempts:
            retry_after = max(1, int(window_seconds - (now - history[0])))
            return False, retry_after
        return True, 0

    def record_failure(self, key: str) -> None:
        self._attempts[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)

    def clear_all(self) -> None:
        self._attempts.clear()


login_limiter = LoginRateLimiter()


# ---------------------------------------------------------------------------
# TOTP 2FA (pyotp with RFC-6238 stdlib fallback)
# ---------------------------------------------------------------------------
def generate_totp_secret() -> str:
    """Generate a 32-character Base32 TOTP secret key."""
    if pyotp is not None:
        return pyotp.random_base32()
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def get_totp_uri(secret: str, email: str, issuer: str = "PhishSim") -> str:
    """Return an otpauth:// provisioning URI for authenticator apps."""
    if pyotp is not None:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
    label = urllib.parse.quote(f"{issuer}:{email}")
    params = urllib.parse.urlencode({"secret": secret, "issuer": issuer, " digits": 6, "period": 30}).replace("+digits", "digits")
    return f"otpauth://totp/{label}?{params}"


def _rfc6238_code(secret: str, counter: int, digits: int = 6) -> str:
    padded = secret.strip().replace(" ", "").upper()
    pad_len = (8 - len(padded) % 8) % 8
    key = base64.b32decode(padded + ("=" * pad_len), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def get_current_totp_code(secret: str, for_time: int | None = None) -> str:
    """Compute the current 6-digit TOTP code (used by tests and verification)."""
    if not secret:
        return ""
    if pyotp is not None and for_time is None:
        return pyotp.TOTP(secret).now()
    ts = int(for_time if for_time is not None else time.time())
    return _rfc6238_code(secret, ts // 30)


def verify_totp_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a 6-digit TOTP code allowing +/- valid_window 30s steps."""
    if not secret or not code:
        return False
    clean = code.strip().replace(" ", "")
    if not clean.isdigit() or len(clean) != 6:
        return False
    if pyotp is not None:
        return bool(pyotp.TOTP(secret).verify(clean, valid_window=valid_window))
    now_step = int(time.time()) // 30
    for offset in range(-valid_window, valid_window + 1):
        if secrets.compare_digest(_rfc6238_code(secret, now_step + offset), clean):
            return True
    return False


def generate_totp_qr_data_uri(provisioning_uri: str) -> str:
    """Generate a data:image/png;base64,... QR code for 2FA enrollment."""
    from .mailer import generate_qr_base64_png
    b64 = generate_qr_base64_png(provisioning_uri)
    return f"data:image/png;base64,{b64}"


# ---------------------------------------------------------------------------
# Enterprise SSO (Microsoft Entra ID, Google Workspace, Okta via Authlib)
# ---------------------------------------------------------------------------
oauth = OAuth() if OAuth is not None else None


def get_configured_sso_providers(app=None) -> dict[str, dict]:
    """Return metadata for supported SSO providers and whether credentials are set."""
    cfg = (app or current_app).config
    entra_tenant = cfg.get("ENTRA_TENANT_ID") or "common"
    okta_domain = (cfg.get("OKTA_DOMAIN") or "example.okta.com").rstrip("/")
    if not okta_domain.startswith("http"):
        okta_domain = f"https://{okta_domain}"

    return {
        "entra": {
            "name": "Microsoft Entra ID",
            "client_id": cfg.get("ENTRA_CLIENT_ID", ""),
            "client_secret": cfg.get("ENTRA_CLIENT_SECRET", ""),
            "server_metadata_url": f"https://login.microsoftonline.com/{entra_tenant}/v2.0/.well-known/openid-configuration",
            "authorize_url": f"https://login.microsoftonline.com/{entra_tenant}/oauth2/v2.0/authorize",
            "enabled": bool(cfg.get("ENTRA_CLIENT_ID") and cfg.get("ENTRA_CLIENT_SECRET")),
        },
        "google": {
            "name": "Google Workspace",
            "client_id": cfg.get("GOOGLE_CLIENT_ID", ""),
            "client_secret": cfg.get("GOOGLE_CLIENT_SECRET", ""),
            "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "enabled": bool(cfg.get("GOOGLE_CLIENT_ID") and cfg.get("GOOGLE_CLIENT_SECRET")),
        },
        "okta": {
            "name": "Okta",
            "client_id": cfg.get("OKTA_CLIENT_ID", ""),
            "client_secret": cfg.get("OKTA_CLIENT_SECRET", ""),
            "server_metadata_url": f"{okta_domain}/.well-known/openid-configuration",
            "authorize_url": f"{okta_domain}/oauth2/v1/authorize",
            "enabled": bool(cfg.get("OKTA_CLIENT_ID") and cfg.get("OKTA_CLIENT_SECRET") and cfg.get("OKTA_DOMAIN")),
        },
    }


def init_sso(app) -> None:
    """Initialize Authlib OAuth clients for Entra ID, Google Workspace, and Okta."""
    app.jinja_env.globals["sso_providers"] = lambda: get_configured_sso_providers(app)
    if oauth is None:
        return
    oauth.init_app(app)
    providers = get_configured_sso_providers(app)
    for key, meta in providers.items():
        if meta["enabled"]:
            oauth.register(
                name=key,
                client_id=meta["client_id"],
                client_secret=meta["client_secret"],
                server_metadata_url=meta["server_metadata_url"],
                client_kwargs={"scope": "openid email profile"},
            )
