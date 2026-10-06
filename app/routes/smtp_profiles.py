"""CRUD routes for Multiple SMTP Profiles (/smtp-profiles)."""
import smtplib

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..audit import log_audit
from ..extensions import db
from ..models import Campaign, SMTPProfile
from ..security import admin_required

bp = Blueprint("smtp_profiles", __name__)


@bp.route("/smtp-profiles")
@login_required
def index():
    profiles = SMTPProfile.query.order_by(SMTPProfile.is_default.desc(), SMTPProfile.name.asc()).all()
    return render_template("smtp_profiles.html", profiles=profiles)


@bp.route("/smtp-profiles/add", methods=["POST"])
@login_required
@admin_required
def add():
    name = request.form.get("name", "").strip()
    host = request.form.get("host", "").strip()
    port = int(request.form.get("port", "1025") or 1025)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    from_address = request.form.get("from_address", "").strip() or "IT Support <it-support@example.com>"
    use_tls = request.form.get("use_tls") == "on"
    is_default = request.form.get("is_default") == "on"

    if not name or not host:
        flash("Profile name and SMTP host are required.", "error")
        return redirect(url_for("smtp_profiles.index"))

    if is_default or SMTPProfile.query.count() == 0:
        SMTPProfile.query.update({"is_default": False})
        is_default = True

    profile = SMTPProfile(
        name=name,
        host=host,
        port=port,
        username=username,
        password=password,
        use_tls=use_tls,
        from_address=from_address,
        is_default=is_default,
    )
    db.session.add(profile)
    db.session.commit()
    log_audit("smtp_profile.added", f"Added SMTP profile '{name}' ({host}:{port})")
    flash(f"SMTP profile “{name}” saved.", "success")
    return redirect(url_for("smtp_profiles.index"))


@bp.route("/smtp-profiles/<int:profile_id>/default", methods=["POST"])
@login_required
@admin_required
def set_default(profile_id: int):
    profile = db.get_or_404(SMTPProfile, profile_id)
    SMTPProfile.query.update({"is_default": False})
    profile.is_default = True
    db.session.commit()
    log_audit("smtp_profile.default", f"Set '{profile.name}' as default SMTP profile")
    flash(f"“{profile.name}” is now the default SMTP profile.", "success")
    return redirect(url_for("smtp_profiles.index"))


@bp.route("/smtp-profiles/<int:profile_id>/test", methods=["POST"])
@login_required
@admin_required
def test_connection(profile_id: int):
    profile = db.get_or_404(SMTPProfile, profile_id)
    try:
        with smtplib.SMTP(profile.host, int(profile.port), timeout=6) as server:
            if profile.use_tls:
                server.starttls()
            if profile.username:
                server.login(profile.username, profile.password)
            server.noop()
        flash(f"Connected to “{profile.name}” ({profile.host}:{profile.port}) successfully.", "success")
    except Exception as exc:
        flash(f"Connection test failed for “{profile.name}”: {exc}", "error")
    return redirect(url_for("smtp_profiles.index"))


@bp.route("/smtp-profiles/<int:profile_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(profile_id: int):
    profile = db.get_or_404(SMTPProfile, profile_id)
    if SMTPProfile.query.count() <= 1:
        flash("Cannot delete the last remaining SMTP profile.", "error")
        return redirect(url_for("smtp_profiles.index"))

    Campaign.query.filter_by(smtp_profile_id=profile.id).update({"smtp_profile_id": None})
    was_default = profile.is_default
    name = profile.name
    db.session.delete(profile)
    db.session.commit()

    if was_default:
        first_remaining = SMTPProfile.query.first()
        if first_remaining:
            first_remaining.is_default = True
            db.session.commit()

    log_audit("smtp_profile.deleted", f"Deleted SMTP profile '{name}'")
    flash(f"Deleted SMTP profile “{name}”.", "info")
    return redirect(url_for("smtp_profiles.index"))
