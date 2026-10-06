"""Email builder, QR-code generator, tracked attachments, and SMTP profile sender."""
import base64
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import html
import io
import re
import smtplib
import threading
from urllib.parse import urlparse

from flask import current_app

from .audit import log_audit, send_webhook
from .extensions import db
from .models import Campaign, Event, SMTPProfile, Target, now_utc

try:
    import qrcode  # type: ignore
except ImportError:
    qrcode = None

_LINK_RE = re.compile(r"\{\{\s*link\s*\}\}", re.IGNORECASE)
_NAME_RE = re.compile(r"\{\{\s*name\s*\}\}", re.IGNORECASE)
_REPORT_RE = re.compile(r"\{\{\s*report_link\s*\}\}", re.IGNORECASE)
_QR_RE = re.compile(r"\{\{\s*qr_code\s*\}\}", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


def has_link(body: str) -> bool:
    """Return True if the email body contains {{link}} or {{qr_code}}."""
    raw = body or ""
    return bool(_LINK_RE.search(raw) or _QR_RE.search(raw))


def generate_qr_base64_png(data: str) -> str:
    """Generate a base64-encoded PNG QR code for the given URL/data."""
    if qrcode is not None:
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")

    # Built-in fallback using reportlab QR matrix + Pillow PNG rendering
    from PIL import Image, ImageDraw
    from reportlab.graphics.barcode.qr import QrCodeWidget

    widget = QrCodeWidget(data)
    widget.barLevel = "M"
    bounds = widget.getBounds()
    # Extract QR matrix directly from QrCodeWidget's internal QRCode object
    qr_obj = widget.qr
    modules = qr_obj.modules
    n = len(modules)
    box_size = 6
    border = 2
    size = (n + border * 2) * box_size
    image = Image.new("RGB", (size, size), "white")
    draw = ImageDraw.Draw(image)
    for r in range(n):
        for c in range(n):
            if modules[r][c]:
                x0 = (c + border) * box_size
                y0 = (r + border) * box_size
                draw.rectangle([x0, y0, x0 + box_size - 1, y0 + box_size - 1], fill="black")
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def generate_qr_img_tag(url: str) -> str:
    """Return an inline HTML <img> tag with a base64 PNG QR code."""
    b64 = generate_qr_base64_png(url)
    return (
        f'<img src="data:image/png;base64,{b64}" '
        f'alt="Scan QR Code" width="168" height="168" '
        f'style="display:inline-block;border:1px solid #e2e8f0;border-radius:8px;padding:6px;background:#ffffff;" />'
    )


def _html_to_plain(html_body: str, landing_url: str, report_url: str) -> str:
    """Convert HTML email body into a readable plain-text fallback."""
    text = re.sub(
        r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        r"\2 (\1)",
        html_body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(r"</(p|div|h[1-6]|li|tr)>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<(br|hr)\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = _TAG_RE.sub("", text)
    text = html.unescape(text)
    lines = [line.strip() for line in text.splitlines()]
    cleaned = "\n".join(line for line in lines if line)
    if landing_url not in cleaned:
        cleaned += f"\n\nLink: {landing_url}"
    if report_url not in cleaned:
        cleaned += f"\n\nThink this message is suspicious? Report it as phishing: {report_url}"
    return cleaned


def _build_html_attachment(target: Target, base_url: str, campaign: Campaign) -> tuple[str, bytes, str]:
    """Generate a benign HTML attachment containing an embedded tracking beacon and link."""
    filename = (campaign.attachment_name or "Document_Preview.html").strip()
    if not filename.lower().endswith(".html"):
        filename += ".html"
    pixel_url = f"{base_url}/track/attachment/{target.token}.png"
    open_url = f"{base_url}/track/attachment/{target.token}/open"
    content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(campaign.subject)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#f8fafc; color:#0f172a; display:grid; place-items:center; min-height:90vh; margin:0; }}
    .box {{ background:#fff; border:1px solid #cbd5e1; border-radius:10px; max-width:440px; padding:28px; text-align:center; box-shadow:0 4px 12px rgba(0,0,0,.06); }}
    .btn {{ display:inline-block; margin-top:16px; padding:10px 18px; background:#2563eb; color:#fff; text-decoration:none; border-radius:6px; font-weight:600; }}
  </style>
</head>
<body>
  <div class="box">
    <h2 style="margin:0 0 8px">Protected Document Preview</h2>
    <p style="color:#64748b;font-size:14px">Prepared for {html.escape(target.full_name)} ({html.escape(target.email)}).</p>
    <a class="btn" href="{open_url}">View Full Document Online</a>
  </div>
  <img src="{pixel_url}" width="1" height="1" alt="" style="display:none" />
</body>
</html>"""
    return filename, content.encode("utf-8"), "text/html"


def _build_pdf_attachment(target: Target, base_url: str, campaign: Campaign) -> tuple[str, bytes, str]:
    """Generate a benign PDF attachment with a tracked link pointing to /track/attachment/<token>/open."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    filename = (campaign.attachment_name or "Security_Notice.pdf").strip()
    if not filename.lower().endswith(".pdf"):
        filename += ".pdf"
    open_url = f"{base_url}/track/attachment/{target.token}/open"

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    _, height = A4
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 60, campaign.subject or "Confidential Document")
    c.setFont("Helvetica", 11)
    c.drawString(50, height - 85, f"Recipient: {target.full_name} <{target.email}>")
    c.drawString(50, height - 115, "This document is protected. Click the link below to authenticate and view:")
    c.setFillColorRGB(0.14, 0.38, 0.92)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 145, ">> Open Protected Document <<")
    c.linkURL(open_url, (45, height - 155, 280, height - 130), relative=0)
    c.showPage()
    c.save()
    return filename, buf.getvalue(), "application/pdf"


def _build_message(campaign: Campaign, target: Target, base_url: str) -> MIMEMultipart:
    landing_url = f"{base_url}/landing/{target.token}"
    pixel_url = f"{base_url}/track/open/{target.token}.png"
    report_url = f"{base_url}/report/{target.token}"

    body = _NAME_RE.sub(target.first_name or "there", campaign.email_body)
    if _LINK_RE.search(body):
        body = _LINK_RE.sub(landing_url, body)
    elif not _QR_RE.search(body):
        body += f'<p><a href="{landing_url}">{landing_url}</a></p>'

    if _QR_RE.search(body):
        qr_img = generate_qr_img_tag(landing_url)
        body = _QR_RE.sub(qr_img, body)

    if _REPORT_RE.search(body):
        body = _REPORT_RE.sub(report_url, body)
    else:
        body += (
            '<hr style="border:none;border-top:1px solid #dddddd;margin:24px 0 12px">'
            '<p style="font-size:12px;color:#888888">Think this message is suspicious? '
            f'<a href="{report_url}">Report it as phishing</a>.</p>'
        )
    html_full = f'{body}<img src="{pixel_url}" width="1" height="1" alt="" />'
    plain_text = _html_to_plain(campaign.email_body, landing_url, report_url)

    alt_part = MIMEMultipart("alternative")
    alt_part.attach(MIMEText(plain_text, "plain", "utf-8"))
    alt_part.attach(MIMEText(html_full, "html", "utf-8"))

    att_type = (campaign.attachment_type or "none").lower()
    if att_type in ("html", "pdf"):
        outer = MIMEMultipart("mixed")
        outer["Subject"] = campaign.subject
        outer["From"] = campaign.sender
        outer["To"] = target.email
        outer.attach(alt_part)

        if att_type == "html":
            fname, raw_bytes, _ = _build_html_attachment(target, base_url, campaign)
            part = MIMEApplication(raw_bytes, _subtype="html")
        else:
            fname, raw_bytes, _ = _build_pdf_attachment(target, base_url, campaign)
            part = MIMEApplication(raw_bytes, _subtype="pdf")
        part.add_header("Content-Disposition", "attachment", filename=fname)
        outer.attach(part)
        return outer

    alt_part["Subject"] = campaign.subject
    alt_part["From"] = campaign.sender
    alt_part["To"] = target.email
    return alt_part


def resolve_base_url(override: str | None = None) -> str:
    """Pick the base URL for tracking links inside outgoing emails."""
    configured = current_app.config["BASE_URL"].rstrip("/")
    if not override:
        return configured
    host = (urlparse( configured).hostname or "").lower()
    if host in ("localhost", "127.0.0.1", ""):
        return override.rstrip("/")
    return configured


def resolve_smtp_settings(campaign: Campaign | None = None) -> dict:
    """Resolve SMTP connection settings from the campaign's SMTPProfile, default profile, or Config."""
    profile = None
    if campaign is not None and campaign.smtp_profile_id:
        profile = db.session.get(SMTPProfile, campaign.smtp_profile_id)
    if profile is None:
        profile = SMTPProfile.query.filter_by(is_default=True).first()
    if profile is None:
        profile = SMTPProfile.query.first()

    if profile is not None:
        return {
            "host": profile.host,
            "port": int(profile.port),
            "user": profile.username or "",
            "password": profile.password or "",
            "use_tls": bool(profile.use_tls),
            "profile_name": profile.name,
        }

    cfg = current_app.config
    return {
        "host": cfg["SMTP_HOST"],
        "port": int(cfg["SMTP_PORT"]),
        "user": cfg.get("SMTP_USER", ""),
        "password": cfg.get("SMTP_PASSWORD", ""),
        "use_tls": bool(cfg.get("SMTP_USE_TLS", False)),
        "profile_name": ".env Fallback",
    }


def _open_smtp(campaign: Campaign | None = None):
    settings = resolve_smtp_settings(campaign)
    server = smtplib.SMTP(settings["host"], settings["port"], timeout=10)
    if settings["use_tls"]:
        server.starttls()
    if settings["user"]:
        server.login(settings["user"], settings["password"])
    return server


def send_test_email(campaign: Campaign, recipient_email: str, base_url_override: str | None = None) -> None:
    """Send a single preview email to `recipient_email` without recording funnel events."""
    base_url = resolve_base_url(base_url_override)
    sample_target = Target(
        campaign_id=campaign.id,
        email=recipient_email,
        first_name="Test",
        last_name="Recipient",
        token="preview-test-token",
    )
    msg = _build_message(campaign, sample_target, base_url)
    msg.replace_header("Subject", f"[TEST] {campaign.subject}")
    with _open_smtp(campaign) as server:
        server.send_message(msg)


def send_Targets(campaign: Campaign, targets: list[Target], base_url_override: str | None = None) -> tuple[int, list[str]]:
    """Send to a specific list of targets. Records 'sent' for each success."""
    base_url = resolve_base_url(base_url_override)
    sent = 0
    errors: list[str] = []
    if not targets:
        return 0, errors

    try:
        with _open_smtp(campaign) as server:
            for t in targets:
                try:
                    server.send_message(_build_message(campaign, t, base_url))
                    if "sent" not in t.types:
                        db.session.add(Event(target_id=t.id, event_type="sent"))
                    sent += 1
                except Exception as exc:
                    errors.append(f"{t.email}: {exc}")
        db.session.commit()
    except Exception as exc:
        Settings = resolve_smtp_settings(campaign)
        errors.append(
            f"Could not connect to SMTP profile '{Settings['profile_name']}' "
            f"({Settings['host']}:{Settings['port']}): {exc}"
        )
    return sent, errors


def send_campaign(campaign: Campaign, base_url_override: str | None = None) -> tuple[int, list[str]]:
    """Manual 'Send now': send to every target in the campaign immediately."""
    sent, errors = send_Targets(campaign, list(campaign.targets), base_url_override)
    if sent:
        campaign.status = "sent"
        campaign.last_batch_at = now_utc()
        db.session.commit()
        send_webhook(
            "campaign.sent",
            f"Campaign '{campaign.name}' sent to {sent} target(s).",
            {"campaign_id": campaign.id, "sent": sent},
        )
    return sent, errors


def send_campaign_async(app, campaign_id: int, base_url_override: str | None = None, user_email: str = "system") -> None:
    """Fire-and-forget background thread to send a campaign without blocking HTTP workers."""
    def _worker():
        with app.app_context():
            campaign = db.session.get(Campaign, campaign_id)
            if not campaign:
                return
            sent, errors = send_campaign(campaign, base_url_override=base_url_override)
            detail = f"Async send completed: {sent} sent, {len(errors)} error(s)"
            log_audit("campaign.sent_async", f"{campaign.name} — {detail}", user_email=user_email)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def send_next_batch(campaign: Campaign) -> tuple[int, list[str]]:
    """Used by the scheduler for scheduled / drip campaigns."""
    unsent = [t for t in campaign.targets if "sent" not in t.types]
    if not unsent:
        campaign.status = "sent"
        db.session.commit()
        return 0, []

    batch = unsent[: campaign.batch_size] if campaign.batch_size > 0 else unsent
    sent, errors = send_Targets(campaign, batch)
    campaign.last_batch_at = now_utc()

    remaining = [t for t in campaign.targets if "sent" not in t.types]
    campaign.status = "sent" if not remaining else "sending"
    db.session.commit()
    return sent, errors
