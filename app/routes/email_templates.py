"""Email template library (admin-managed). Every template must include {{link}} or {{qr_code}}."""
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..audit import log_audit
from ..extensions import db
from ..mailer import has_link
from ..models import Template
from ..security import admin_required

bp = Blueprint("templates", __name__)


@bp.route("/templates")
@login_required
def index():
    templates = Template.query.order_by(Template.difficulty, Template.name).all()
    return render_template("templates.html", templates=templates)


@bp.route("/templates/add", methods=["POST"])
@login_required
@admin_required
def add():
    name = request.form.get("name", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "")
    difficulty = request.form.get("difficulty", "medium")

    if not name or not subject or not body:
        flash("Name, subject, and body are required.", "error")
    elif not has_link(body):
        flash("The body must include {{link}} or {{qr_code}} so targets have an action.", "error")
    else:
        db.session.add(Template(name=name, subject=subject, body=body, difficulty=difficulty))
        db.session.commit()
        log_audit("template.added", f"Added template '{name}' ({difficulty})")
        flash(f"Template “{name}” added.", "success")
    return redirect(url_for("templates.index"))


@bp.route("/templates/<int:template_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(template_id: int):
    tpl = db.get_or_404(Template, template_id)
    name = tpl.name
    db.session.delete(tpl)
    db.session.commit()
    log_audit("template.deleted", f"Deleted template '{name}'")
    flash("Template deleted.", "success")
    return redirect(url_for("templates.index"))
