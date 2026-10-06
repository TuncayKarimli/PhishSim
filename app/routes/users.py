"""User management and audit log (admin only)."""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from ..audit import log_audit
from ..extensions import db
from ..models import User, AuditLog
from ..security import admin_required

bp = Blueprint("users", __name__)


@bp.route("/users")
@login_required
@admin_required
def index():
    return render_template("users.html", users=User.query.order_by(User.email).all())


@bp.route("/users/add", methods=["POST"])
@login_required
@admin_required
def add():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    if not email or not password:
        flash("Email and password are required.", "error")
    elif len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
    elif User.query.filter_by(email=email).first():
        flash("A user with that email already exists.", "error")
    else:
        final_role = "admin" if role == "admin" else "viewer"
        u = User(email=email, role=final_role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        log_audit("user.added", f"Added {final_role} account {email}")
        flash(f"Added {final_role} {email}.", "success")
    return redirect(url_for("users.index"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You can't delete your own account.", "error")
    else:
        email = user.email
        db.session.delete(user)
        db.session.commit()
        log_audit("user.deleted", f"Deleted user account {email}")
        flash("User deleted.", "success")
    return redirect(url_for("users.index"))


@bp.route("/audit")
@login_required
@admin_required
def audit():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template("audit.html", logs=logs)
