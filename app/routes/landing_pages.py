"""CRUD routes for Custom Landing Pages (/landing-pages)."""
import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..audit import log_audit
from ..extensions import db
from ..models import Campaign, LandingPage
from ..security import admin_required

bp = Blueprint("landing_pages", __name__)


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "custom-page"


@bp.route("/landing-pages")
@login_required
def index():
    pages = LandingPage.query.order_by(LandingPage.id.asc()).all()
    return render_template("landing_pages.html", pages=pages)


@bp.route("/landing-pages/add", methods=["POST"])
@login_required
@admin_required
def add():
    name = request.form.get("name", "").strip()
    html_body = request.form.get("html_body", "").strip()
    if not name or not html_body:
        flash("Landing page name and HTML body are required.", "error")
        return redirect(url_for("landing_pages.index"))

    base_slug = _slugify(name)
    slug = base_slug
    idx = 2
    while LandingPage.query.filter_by(slug=slug).first() is not None:
        slug = f"{base_slug}-{idx}"
        idx += 1

    page = LandingPage(name=name, slug=slug, html_body=html_body)
    db.session.add(page)
    db.session.commit()
    log_audit("landing_page.added", f"Created custom landing page '{name}' ({slug})")
    flash(f"Custom landing page “{name}” saved.", "success")
    return redirect(url_for("landing_pages.index"))


@bp.route("/landing-pages/<int:page_id>/edit", methods=["POST"])
@login_required
@admin_required
def edit(page_id: int):
    page = db.get_or_404(LandingPage, page_id)
    name = request.form.get("name", "").strip()
    html_body = request.form.get("html_body", "").strip()
    if not name or not html_body:
        flash("Name and HTML body are required.", "error")
        return redirect(url_for("landing_pages.index"))

    page.name = name
    page.html_body = html_body
    db.session.commit()
    log_audit("landing_page.edited", f"Updated custom landing page '{name}'")
    flash(f"Updated landing page “{name}”.", "success")
    return redirect(url_for("landing_pages.index"))


@bp.route("/landing-pages/<int:page_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete(page_id: int):
    page = db.get_or_404(LandingPage, page_id)
    Campaign.query.filter_by(custom_landing_id=page.id).update({"custom_landing_id": None})
    name = page.name
    db.session.delete(page)
    db.session.commit()
    log_audit("landing_page.deleted", f"Deleted custom landing page '{name}'")
    flash(f"Deleted landing page “{name}”.", "info")
    return redirect(url_for("landing_pages.index"))
