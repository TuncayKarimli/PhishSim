"""Admin authentication: local login, TOTP 2FA, Enterprise SSO (Entra/Google/Okta), and password/2FA management."""
import secrets
import urllib.parse

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from ..audit import log_audit
from ..extensions import db
from ..models import User
from ..security import (
    generate_totp_qr_data_uri,
    generate_totp_secret,
    get_configured_sso_providers,
    get_totp_uri,
    login_limiter,
    oauth,
    verify_totp_code,
)

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        max_attempts = current_app.config.get("LOGIN_RATE_LIMIT", 5)
        window = current_app.config.get("LOGIN_RATE_WINDOW", 60)
        allowed, retry_after = login_limiter.is_allowed(ip, max_attempts, window)
        if not allowed:
            log_audit("auth.rate_limited", f"Too many login attempts from {ip}", user_email="anonymous")
            flash(f"Too many sign-in attempts. Please wait {retry_after}s and try again.", "error")
            return render_template("login.html"), 429

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_limiter.reset(ip)
            if user.totp_enabled and user.totp_secret:
                session["pending_2fa_user_id"] = user.id
                return redirect(url_for("auth.verify_2fa"))
            login_user(user)
            log_audit("auth.login", "Signed in successfully", user_email=user.email)
            return redirect(url_for("dashboard.index"))

        login_limiter.record_failure(ip)
        log_audit("auth.login_failed", f"Failed login for {email or 'empty email'}", user_email=email or "anonymous")
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@bp.route("/login/2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))
    user = db.session.get(User, int(pending_id))
    if not user or not user.totp_enabled:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("totp_code", "").strip()
        if verify_totp_code(user.totp_secret, code):
            session.pop("pending_2fa_user_id", None)
            login_user(user)
            log_audit("auth.login_2fa", "Signed in with TOTP 2FA", user_email=user.email)
            return redirect(url_for("dashboard.index"))
        log_audit("auth.2fa_failed", "Invalid TOTP 2FA code", user_email=user.email)
        flash("Invalid 6-digit authenticator code. Please try again.", "error")

    return render_template("totp_verify.html", user=user)


@bp.route("/auth/sso/<provider>")
def sso_login(provider: str):
    provider = provider.lower().strip()
    providers = get_configured_sso_providers()
    if provider not in providers:
        flash(f"Unsupported SSO provider '{provider}'.", "error")
        return redirect(url_for("auth.login"))

    meta = providers[provider]
    if not meta["enabled"]:
        flash(
            f"{meta['name']} SSO is not configured yet. Set its Client ID and Secret in .env.",
            "info",
        )
        return redirect(url_for("auth.login"))

    redirect_uri = url_for("auth.sso_callback", provider=provider, _external=True)
    state = secrets.token_urlsafe(16)
    session["sso_state"] = state

    if oauth is not None and hasattr(oauth, provider):
        client = getattr(oauth, provider)
        if client is not None:
            return client.authorize_redirect(redirect_uri, state=state)

    params = urllib.parse.urlencode(
        {
            "client_id": meta["client_id"],
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    return redirect(f"{meta['authorize_url']}?{params}")


@bp.route("/auth/sso/<provider>/callback")
def sso_callback(provider: str):
    provider = provider.lower().strip()
    providers = get_configured_sso_providers()
    if provider not in providers:
        flash("Unsupported SSO provider.", "error")
        return redirect(url_for("auth.login"))

    expected_state = session.pop("sso_state", None)
    returned_state = request.args.get("state")
    if expected_state and returned_state != expected_state:
        flash("Invalid SSO state parameter.", "error")
        return redirect(url_for("auth.login"))

    email = ""
    sub = ""
    if oauth is not None and hasattr(oauth, provider):
        client = getattr(oauth, provider)
        if client is not None:
            try:
                token = client.authorize_access_token()
                userinfo = token.get("userinfo") or client.userinfo()
                email = (userinfo.get("email") or "").strip().lower()
                sub = str(userinfo.get("sub") or "")
            except Exception as exc:
                flash(f"SSO authentication failed: {exc}", "error")
                return redirect(url_for("auth.login"))

    # Allow simulated/test callback assertions when testing OIDC flow locally
    if not email and current_app.config.get("TESTING"):
        email = (request.args.get("mock_email") or "").strip().lower()
        sub = request.args.get("mock_sub") or "sso-sub-1"

    if not email:
        flash("Could not retrieve email claim from SSO identity provider.", "error")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if user is None:
        if not current_app.config.get("SSO_AUTO_PROVISION", True):
            log_audit("auth.sso_denied", f"Unprovisioned SSO user {email} ({provider})", user_email=email)
            flash("Your account is not provisioned in PhishSim. Contact an administrator.", "error")
            return redirect(url_for("auth.login"))
        default_role = current_app.config.get("SSO_DEFAULT_ROLE", "viewer")
        role = "admin" if default_role == "admin" else "viewer"
        user = User(
            email=email,
            role=role,
            sso_provider=provider,
            sso_subject=sub,
        )
        user.set_password(secrets.token_urlsafe(24))
        db.session.add(user)
        db.session.commit()
        log_audit("auth.sso_provisioned", f"Auto-provisioned {role} via {provider}", user_email=email)
    else:
        user.sso_provider = provider
        if sub:
            user.sso_subject = sub
        db.session.commit()

    login_user(user)
    log_audit("auth.sso_login", f"Signed in via {providers[provider]['name']}", user_email=user.email)
    return redirect(url_for("dashboard.index"))


@bp.route("/logout")
@login_required
def logout():
    log_audit("auth.logout", "Signed out")
    logout_user()
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    # Ensure a pending secret exists in session for 2FA setup preview
    if not current_user.totp_enabled and "setup_totp_secret" not in session:
        session["setup_totp_secret"] = generate_totp_secret()

    setup_secret = current_user.totp_secret if current_user.totp_enabled else session.get("setup_totp_secret", "")
    totp_uri = get_totp_uri(setup_secret, current_user.email) if setup_secret else ""
    totp_qr = generate_totp_qr_data_uri(totp_uri) if totp_uri else ""

    if request.method == "POST":
        action = request.form.get("form_action", "password")

        if action == "enable_2fa":
            code = request.form.get("totp_code", "").strip()
            secret = session.get("setup_totp_secret") or setup_secret
            if verify_totp_code(secret, code):
                current_user.totp_secret = secret
                current_user.totp_enabled = True
                db.session.commit()
                session.pop("setup_totp_secret", None)
                log_audit("auth.2fa_enabled", "Enabled TOTP two-factor authentication")
                flash("Two-factor authentication (TOTP) is now enabled on your account.", "success")
                return redirect(url_for("auth.change_password"))
            flash("Invalid 6-digit verification code. Scan the QR code and try again.", "error")

        elif action == "disable_2fa":
            current_user.totp_enabled = False
            current_user.totp_secret = ""
            db.session.commit()
            log_audit("auth.2fa_disabled", "Disabled TOTP two-factor authentication")
            flash("Two-factor authentication has been disabled.", "info")
            return redirect(url_for("auth.change_password"))

        else:
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")

            if not current_user.check_password(current_pw):
                flash("Current password is incorrect.", "error")
            elif len(new_pw) < 8:
                flash("New password must be at least 8 characters.", "error")
            elif new_pw != confirm_pw:
                flash("New password and confirmation do not match.", "error")
            else:
                current_user.set_password(new_pw)
                db.session.commit()
                log_audit("auth.password_changed", "User updated their own password")
                flash("Your password has been updated.", "success")
                return redirect(url_for("dashboard.index"))

    return render_template(
        "password.html",
        setup_secret=setup_secret,
        totp_qr=totp_qr,
    )
