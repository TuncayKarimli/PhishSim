"""Admin dashboard: campaigns, target import, sending, CSV/PDF export, and Time-Series Analytics."""
from collections import OrderedDict
import csv
from datetime import datetime
import io

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.styles import getSampleStyleSheet

from ..audit import log_audit
from ..extensions import db
from ..mailer import (
    generate_qr_base64_png,
    resolve_base_url,
    send_campaign,
    send_campaign_async,
    send_test_email,
)
from ..models import (
    FUNNEL,
    Campaign,
    Event,
    LandingPage,
    SMTPProfile,
    Target,
    Template,
    now_utc,
)
from ..security import admin_required

bp = Blueprint("dashboard", __name__)


def _compute_timeseries() -> dict:
    """Compute Month-over-Month (monthly) and Quarter-over-Quarter (quarterly) click & report rates."""
    campaigns = Campaign.query.order_by(Campaign.created_at.asc(), Campaign.id.asc()).all()
    monthly_buckets: OrderedDict[str, dict] = OrderedDict()
    quarterly_buckets: OrderedDict[str, dict] = OrderedDict()

    for c in campaigns:
        dt = c.created_at or now_utc()
        m_key = dt.strftime("%Y-%m")
        q_num = (dt.month - 1) // 3 + 1
        q_key = f"{dt.year}-Q{q_num}"

        s = c.stats()
        for bucket_map, key in ((monthly_buckets, m_key), (quarterly_buckets, q_key)):
            b = bucket_map.setdefault(
                key,
                {"period": key, "total": 0, "sent": 0, "opened": 0, "clicked": 0, "submitted": 0, "reported": 0},
            )
            b["total"] += s["total"]
            b["sent"] += s["sent"]
            b["opened"] += s["opened"]
            b["clicked"] += s["clicked"]
            b["submitted"] += s["submitted"]
            b["reported"] += s["reported"]

    def _finalize(bucket_map: OrderedDict[str, dict]) -> list[dict]:
        out = []
        for b in bucket_map.values():
            denom = b["sent"] or b["total"] or 1
            b["click_rate"] = round((b["clicked"] / denom) * 100, 1) if (b["sent"] or b["total"]) else 0.0
            b["submit_rate"] = round((b["submitted"] / denom) * 100, 1) if (b["sent"] or b["total"]) else 0.0
            b["report_rate"] = round((b["reported"] / denom) * 100, 1) if (b["sent"] or b["total"]) else 0.0
            out.append(b)
        return out

    return {
        "monthly": _finalize(monthly_buckets),
        "quarterly": _finalize(quarterly_buckets),
    }


@bp.route("/api/analytics/timeseries")
@login_required
def api_timeseries():
    """JSON endpoint returning Month-over-Month and Quarter-over-Quarter funnel trends."""
    return jsonify(_compute_timeseries())


@bp.route("/api/qr-preview")
@login_required
def api_qr_preview():
    """Return a base64 PNG QR code for live preview in the campaign editor."""
    sample_url = request.args.get("url") or f"{resolve_base_url(request.host_url)}/landing/preview-token"
    return jsonify({"data_uri": f"data:image/png;base64,{generate_qr_base64_png(sample_url)}"})


@bp.route("/")
@login_required
def index():
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    stats = {c.id: c.stats() for c in campaigns}

    total_targets = sum(s["total"] for s in stats.values())
    total_sent = sum(s["sent"] for s in stats.values())
    total_opened = sum(s["opened"] for s in stats.values())
    total_clicked = sum(s["clicked"] for s in stats.values())
    total_submitted = sum(s["submitted"] for s in stats.values())
    total_reported = sum(s["reported"] for s in stats.values())
    overview = {
        "campaigns": len(campaigns),
        "active": sum(1 for c in campaigns if c.status in ("sending", "scheduled")),
        "total": total_targets,
        "sent": total_sent,
        "opened": total_opened,
        "clicked": total_clicked,
        "submitted": total_submitted,
        "reported": total_reported,
        "pct": {
            "opened": round((total_opened / total_targets) * 100, 1) if total_targets else 0.0,
            "clicked": round((total_clicked / total_targets) * 100, 1) if total_targets else 0.0,
            "submitted": round((total_submitted / total_targets) * 100, 1) if total_targets else 0.0,
            "reported": round((total_reported / total_targets) * 100, 1) if total_targets else 0.0,
        },
    }
    timeseries = _compute_timeseries()
    return render_template(
        "dashboard.html",
        campaigns=campaigns,
        stats=stats,
        overview=overview,
        timeseries=timeseries,
    )


def _parse_targets(csv_file, raw_lines: str) -> list[tuple[str, str, str, str, str, str]]:
    """Return a de-duplicated list of (email, first_name, last_name, department, location, business_unit)."""
    found: dict[str, tuple[str, str, str, str, str, str]] = {}

    if csv_file and csv_file.filename:
        text = io.TextIOWrapper(csv_file.stream, encoding="utf-8", errors="ignore").read()
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if lines:
            first_row = next(csv.reader([lines[0]]))
            header_tokens = {c.strip().lower() for c in first_row}
            if "email" in header_tokens or any("@" not in c for c in first_row[:1]):
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    norm = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
                    email = norm.get("email", "").lower()
                    if not email or "@" not in email:
                        continue
                    first = norm.get("first_name") or norm.get("firstname") or norm.get("first") or ""
                    last = norm.get("last_name") or norm.get("lastname") or norm.get("last") or ""
                    dept = norm.get("department") or norm.get("dept") or ""
                    loc = norm.get("location") or norm.get("office") or ""
                    bu = norm.get("business_unit") or norm.get("business unit") or norm.get("unit") or ""
                    found[email] = (email, first, last, dept, loc, bu)
            else:
                for row in csv.reader(io.StringIO(text)):
                    if not row:
                        continue
                    email = row[0].strip().lower()
                    if not email or "@" not in email:
                        continue
                    first = row[1].strip() if len(row) > 1 else ""
                    last = row[2].strip() if len(row) > 2 else ""
                    dept = row[3].strip() if len(row) > 3 else ""
                    loc = row[4].strip() if len(row) > 4 else ""
                    bu = row[5].strip() if len(row) > 5 else ""
                    found[email] = (email, first, last, dept, loc, bu)

    for line in (raw_lines or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        email = parts[0].lower()
        if "@" in email:
            first = parts[1] if len(parts) > 1 else ""
            last = parts[2] if len(parts) > 2 else ""
            dept = parts[3] if len(parts) > 3 else ""
            loc = parts[4] if len(parts) > 4 else ""
            bu = parts[5] if len(parts) > 5 else ""
            found.setdefault(email, (email, first, last, dept, loc, bu))

    return list(found.values())


def _parse_dt(val: str) -> datetime | None:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val)
    except ValueError:
        return None


def _templates_for_js() -> dict:
    return {
        str(t.id): {"name": t.name, "difficulty": t.difficulty, "subject": t.subject, "body": t.body}
        for t in Template.query.order_by(Template.id).all()
    }


def _parse_int_or_none(val: str | None) -> int | None:
    if not val or not str(val).strip().isdigit():
        return None
    return int(val)


@bp.route("/campaigns/new", methods=["GET", "POST"])
@login_required
@admin_required
def new_campaign():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        sender = request.form.get("sender", "").strip() or "IT Support <no-reply@example.com>"
        difficulty = request.form.get("difficulty", "medium")
        subject = request.form.get("subject", "").strip()
        email_body = request.form.get("email_body", "").strip()
        landing_type = request.form.get("landing_type", "credentials")
        landing_page = request.form.get("landing_page", "custom")
        landing_company = request.form.get("landing_company", "").strip()
        smtp_profile_id = _parse_int_or_none(request.form.get("smtp_profile_id"))
        custom_landing_id = _parse_int_or_none(request.form.get("custom_landing_id"))
        attachment_type = request.form.get("attachment_type", "none").strip().lower()
        attachment_name = request.form.get("attachment_name", "").strip()
        scheduled_at = _parse_dt(request.form.get("scheduled_at", "").strip())
        batch_size = max(0, int(request.form.get("batch_size") or 0))
        batch_interval = max(0, int(request.form.get("batch_interval") or 0))
        rows = _parse_targets(request.files.get("csv_file"), request.form.get("targets_text", ""))

        if not (name and subject and email_body and rows):
            flash("Please fill in name, subject, email body, and at least one target.", "error")
            return render_template(
                "campaign_new.html",
                tpl_map=_templates_for_js(),
                smtp_profiles=SMTPProfile.query.order_by(SMTPProfile.is_default.desc(), SMTPProfile.name.asc()).all(),
                custom_landings=LandingPage.query.order_by(LandingPage.name.asc()).all(),
            )

        campaign = Campaign(
            name=name,
            sender=sender,
            difficulty=difficulty if difficulty in ("easy", "medium", "hard") else "medium",
            subject=subject,
            email_body=email_body,
            landing_type="click" if landing_type == "click" else "credentials",
            landing_page=landing_page if landing_page in ("outlook", "gmail", "custom", "custom_template") else "custom",
            landing_company=landing_company,
            smtp_profile_id=smtp_profile_id,
            custom_landing_id=custom_landing_id if landing_page == "custom_template" or custom_landing_id else None,
            attachment_type=attachment_type if attachment_type in ("none", "html", "pdf") else "none",
            attachment_name=attachment_name,
            status="scheduled" if scheduled_at else "draft",
            scheduled_at=scheduled_at,
            batch_size=batch_size,
            batch_interval=batch_interval,
        )
        db.session.add(campaign)
        db.session.flush()
        for email, first, last, dept, loc, bu in rows:
            db.session.add(
                Target(
                    campaign_id=campaign.id,
                    email=email,
                    first_name=first,
                    last_name=last,
                    department=dept,
                    location=loc,
                    business_unit=bu,
                )
            )
        db.session.commit()
        log_audit("campaign.created", f"Created campaign #{campaign.id} '{campaign.name}' with {len(rows)} target(s)")
        flash(f"Campaign “{campaign.name}” created with {len(rows)} target(s).", "success")
        return redirect(url_for("dashboard.campaign_detail", campaign_id=campaign.id))

    return render_template(
        "campaign_new.html",
        tpl_map=_templates_for_js(),
        smtp_profiles=SMTPProfile.query.order_by(SMTPProfile.is_default.desc(), SMTPProfile.name.asc()).all(),
        custom_landings=LandingPage.query.order_by(LandingPage.name.asc()).all(),
    )


@bp.route("/campaigns/<int:campaign_id>")
@login_required
def campaign_detail(campaign_id: int):
    campaign = db.get_or_404(Campaign, campaign_id)
    return render_template(
        "campaign_detail.html",
        campaign=campaign,
        stats=campaign.stats(),
        stages=FUNNEL,
    )


@bp.route("/campaigns/<int:campaign_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_campaign(campaign_id: int):
    campaign = db.get_or_404(Campaign, campaign_id)
    if request.method == "POST":
        campaign.name = request.form.get("name", "").strip() or campaign.name
        campaign.sender = request.form.get("sender", "").strip() or campaign.sender
        diff = request.form.get("difficulty", campaign.difficulty)
        if diff in ("easy", "medium", "hard"):
            campaign.difficulty = diff
        campaign.subject = request.form.get("subject", "").strip() or campaign.subject
        campaign.email_body = request.form.get("email_body", "").strip() or campaign.email_body
        lt = request.form.get("landing_type", campaign.landing_type)
        campaign.landing_type = "click" if lt == "click" else "credentials"
        lp = request.form.get("landing_page", campaign.landing_page)
        if lp in ("outlook", "gmail", "custom", "custom_template"):
            campaign.landing_page = lp
        campaign.landing_company = request.form.get("landing_company", "").strip()
        campaign.smtp_profile_id = _parse_int_or_none(request.form.get("smtp_profile_id"))
        custom_lid = _parse_int_or_none(request.form.get("custom_landing_id"))
        campaign.custom_landing_id = custom_lid if lp == "custom_template" or custom_lid else None
        att_type = request.form.get("attachment_type", campaign.attachment_type or "none").strip().lower()
        if att_type in ("none", "html", "pdf"):
            campaign.attachment_type = att_type
        campaign.attachment_name = request.form.get("attachment_name", "").strip()
        db.session.commit()
        log_audit("campaign.edited", f"Updated campaign #{campaign.id} '{campaign.name}'")
        flash("Campaign updated. Click 'Send now' to re-send with the new content.", "success")
        return redirect(url_for("dashboard.campaign_detail", campaign_id=campaign.id))
    return render_template(
        "campaign_edit.html",
        campaign=campaign,
        tpl_map=_templates_for_js(),
        smtp_profiles=SMTPProfile.query.order_by(SMTPProfile.is_default.desc(), SMTPProfile.name.asc()).all(),
        custom_landings=LandingPage.query.order_by(LandingPage.name.asc()).all(),
    )


@bp.route("/campaigns/<int:campaign_id>/send", methods=["POST"])
@login_required
@admin_required
def send(campaign_id: int):
    campaign = db.get_or_404(Campaign, campaign_id)
    base = resolve_base_url(request.host_url)
    mode = request.form.get("mode", "sync")

    if mode == "async":
        app = current_app._get_current_object()
        send_campaign_async(app, campaign.id, base_url_override=request.host_url, user_email=current_user.email)
        log_audit("campaign.queued", f"Queued background send for campaign #{campaign.id} '{campaign.name}'")
        flash(f"Queued background send for {len(campaign.targets)} target(s) (links point to {base}).", "info")
        return redirect(url_for("dashboard.campaign_detail", campaign_id=campaign.id))

    sent, errors = send_campaign(campaign, base_url_override=request.host_url)
    log_audit("campaign.sent", f"Sent campaign #{campaign.id} '{campaign.name}' to {sent} target(s)")
    if sent:
        flash(f"Sent {sent} email(s) (links point to {base}).", "success")
    for err in errors:
        flash(err, "error")
    return redirect(url_for("dashboard.campaign_detail", campaign_id=campaign.id))


@bp.route("/campaigns/<int:campaign_id>/send-test", methods=["POST"])
@login_required
@admin_required
def send_test(campaign_id: int):
    campaign = db.get_or_404(Campaign, campaign_id)
    recipient = request.form.get("test_email", "").strip() or current_user.email
    try:
        send_test_email(campaign, recipient, base_url_override=request.host_url)
        log_audit("campaign.test_sent", f"Sent test email for campaign #{campaign.id} to {recipient}")
        flash(f"Test email sent to {recipient}.", "success")
    except Exception as exc:
        flash(f"Could not send test email: {exc}", "error")
    return redirect(url_for("dashboard.campaign_detail", campaign_id=campaign.id))


@bp.route("/campaigns/<int:campaign_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_campaign(campaign_id: int):
    campaign = db.get_or_404(Campaign, campaign_id)
    cid, cname = campaign.id, campaign.name
    db.session.delete(campaign)
    db.session.commit()
    log_audit("campaign.deleted", f"Deleted campaign #{cid} '{cname}'")
    flash("Campaign deleted.", "info")
    return redirect(url_for("dashboard.index"))


@bp.route("/campaigns/<int:campaign_id>/export.csv")
@login_required
def export_csv(campaign_id: int):
    c = db.get_or_404(Campaign, campaign_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "email",
            "first_name",
            "last_name",
            "department",
            "location",
            "business_unit",
            "status",
            "sent",
            "opened",
            "attachment_opened",
            "clicked",
            "submitted",
            "reported",
        ]
    )
    for t in c.targets:
        types = t.types
        w.writerow(
            [
                t.email,
                t.first_name,
                t.last_name,
                t.department,
                t.location,
                t.business_unit,
                t.status,
                int("sent" in types),
                int("opened" in types),
                int("attachment_opened" in types),
                int("clicked" in types),
                int("submitted" in types),
                int("reported" in types),
            ]
        )
    log_audit("campaign.export_csv", f"Exported CSV for campaign #{c.id} '{c.name}'")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="campaign_{c.id}.csv"'},
    )


@bp.route("/campaigns/<int:campaign_id>/export.pdf")
@login_required
def export_pdf(campaign_id: int):
    c = db.get_or_404(Campaign, campaign_id)
    s = c.stats()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40,
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"<b>PhishSim Report — {c.name}</b>", styles["Title"]),
        Paragraph(
            f"Difficulty: <b>{c.difficulty}</b> · Subject: {c.subject} · Sender: {c.sender}",
            styles["Normal"],
        ),
        Spacer(1, 14),
        Paragraph("<b>Funnel Summary</b>", styles["Heading2"]),
    ]
    summary_rows = [["Stage", "Count", "Percent of targets"]]
    for stage in (*FUNNEL, "attachment_opened", "reported"):
        label = stage.replace("_", " ").capitalize()
        summary_rows.append([label, str(s[stage]), f"{s['pct'][stage]}%"])
    t1 = Table(summary_rows, hAlign="LEFT", colWidths=[160, 80, 120])
    t1.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [t1, Spacer(1, 18), Paragraph("<b>Targets</b>", styles["Heading2"])]

    target_rows = [["Name", "Email", "Department", "Furthest stage", "Reported"]]
    for t in c.targets:
        target_rows.append([t.full_name, t.email, t.department or "—", t.status, "yes" if t.reported else "—"])
    t2 = Table(target_rows, hAlign="LEFT", colWidths=[110, 150, 90, 80, 55])
    t2.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(t2)
    doc.build(story)
    log_audit("campaign.export_pdf", f"Exported PDF for campaign #{c.id} '{c.name}'")
    return Response(
        buf.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="campaign_{c.id}.pdf"'},
    )
