"""Public (unauthenticated) tracking endpoints hit by the target's browser.

    GET  /track/open/<token>.png        -> records "opened", returns 1x1 pixel
    GET  /track/attachment/<token>.png  -> records "attachment_opened" + "opened", returns 1x1 pixel
    GET  /track/attachment/<token>/open -> records "attachment_opened" + "clicked", redirects to landing
    GET  /landing/<token>               -> records "clicked", shows fake login (built-in or custom) or training
    POST /submit/<token>                -> records "submitted" (password DISCARDED)
    GET  /report/<token>                -> records "reported" (the GOOD outcome)
    GET  /training                      -> awareness page (after a "failure")
    GET  /training/<token>              -> contextual awareness page with campaign breakdown
"""
import base64
import html
import re

from flask import Blueprint, Response, redirect, render_template, request, url_for

from ..audit import send_webhook
from ..extensions import db
from ..models import Event, LandingPage, Target
from ..security import csrf_exempt

bp = Blueprint("tracking", __name__)

_PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

# Filter to prevent false opens/clicks from mail gateways, scanners, and prefetchers.
_SCANNER_HINTS = (
    "bot", "crawl", "spider", "preview", "proofpoint", "mimecast",
    "barracuda", "forcepoint", "bitdefender", "cloudmark", "fireeye",
    "safelinks", "defender", "googleimageproxy", "headlesschrome",
    "phantomjs", "python-requests", "curl/", "wget/", "urlscan",
)

_PREFETCH_HEADERS = ("X-Purpose", "Purpose", "Sec-Purpose", "X-Moz", "X-Scanner")


def _is_scanner(req) -> bool:
    """Detect automated email link scanners, image proxies, and browser prefetchers."""
    if req.method == "HEAD":
        return True
    ua = (req.headers.get("User-Agent") or "").lower()
    if any(hint in ua for hint in _SCANNER_HINTS):
        return True
    for header in _PREFETCH_HEADERS:
        val = (req.headers.get(header) or "").lower()
        if val in ("preview", "prefetch", "scan", "1", "true"):
            return True
    return False


def _record(target: Target, event_type: str) -> None:
    db.session.add(
        Event(
            target_id=target.id,
            event_type=event_type,
            ip=request.remote_addr or "",
            user_agent=(request.headers.get("User-Agent") or "")[:255],
        )
    )
    db.session.commit()


def _campaign_red_flags(campaign) -> list[dict]:
    """Derive specific red flags from the campaign's actual sender, subject, and body."""
    if not campaign:
        return []
    flags = []
    subj_lower = (campaign.subject or "").lower()
    body_lower = (campaign.email_body or "").lower()
    combined = f"{subj_lower} {body_lower}"

    flags.append(
        {
            "title": "Unverified sender address",
            "detail": f"The message claimed to be from “{campaign.sender}”. Always verify the full domain and check via a separate channel before acting.",
        }
    )
    if any(
        w in combined
        for w in (
            "urgent",
            "24 hours",
            "immediately",
            "today",
            "expir",
            "suspend",
            "lock",
            "delay",
            "action required",
        )
    ):
        flags.append(
            {
                "title": "Manufactured urgency or pressure",
                "detail": f"The subject (“{campaign.subject}”) or body used time pressure to push you into clicking before verifying.",
            }
        )
    if any(w in combined for w in ("won", "prize", "gift card", "congratulations", "reward", "$")):
        flags.append(
            {
                "title": "Too-good-to-be-true lure",
                "detail": "Unexpected rewards, gift cards, or financial windfalls are classic hooks designed to bypass caution.",
            }
        )
    if (campaign.attachment_type or "none") != "none":
        flags.append(
            {
                "title": f"Unexpected {(campaign.attachment_type or '').upper()} attachment",
                "detail": "Attackers frequently attach HTML or PDF files that redirect to credential-harvesting portals.",
            }
        )
    if "{{qr_code}}" in body_lower:
        flags.append(
            {
                "title": "QR Code ('Quishing') redirect",
                "detail": "QR codes hide the destination URL and move you from your protected corporate workstation to a mobile browser.",
            }
        )
    if campaign.landing_type == "credentials":
        page_label = (campaign.landing_page or "custom").capitalize()
        flags.append(
            {
                "title": f"Unexpected {page_label} credential prompt",
                "detail": "Clicking an email link that immediately asks for your username and password is the #1 way accounts are compromised.",
            }
        )
    else:
        flags.append(
            {
                "title": "Embedded external action link",
                "detail": "Instead of navigating to the service via your own bookmark, the email directed you through a tracked link.",
            }
        )
    return flags


def _render_custom_landing(page: LandingPage, target: Target, company: str) -> str:
    """Safely substitute placeholders in a custom LandingPage HTML template."""
    submit_url = url_for("tracking.submit", token=target.token)
    rendered = page.html_body
    replacements = {
        r"\{\{\s*submit_url\s*\}\}": submit_url,
        r"\{\{\s*email\s*\}\}": html.escape(target.email),
        r"\{\{\s*name\s*\}\}": html.escape(target.full_name),
        r"\{\{\s*company\s*\}\}": html.escape(company),
    }
    for pattern, val in replacements.items():
        rendered = re.sub(pattern, val, rendered, flags=re.IGNORECASE)

    # Ensure form posts to submit_url and contains the honeypot input if omitted
    if "website_url" not in rendered and "</form>" in rendered.lower():
        honeypot_html = (
            '<div style="position:absolute;left:-9999px;opacity:0;pointer-events:none;" aria-hidden="true">'
            '<input type="text" name="website_url" tabindex="-1" autocomplete="off">'
            "</div></form>"
        )
        rendered = re.sub(r"</form>", honeypot_html, rendered, count=1, flags=re.IGNORECASE)
    return rendered


@bp.route("/track/open/<token>.png")
def track_open(token: str):
    target = Target.query.filter_by(token=token).first()
    if target and not _is_scanner(request):
        _record(target, "opened")
    return Response(_PIXEL, mimetype="image/png", headers={"Cache-Control": "no-store"})


@bp.route("/track/attachment/<token>.png")
def track_attachment_pixel(token: str):
    target = Target.query.filter_by(token=token).first()
    if target and not _is_scanner(request):
        _record(target, "opened")
        _record(target, "attachment_opened")
    return Response(_PIXEL, mimetype="image/png", headers={"Cache-Control": "no-store"})


@bp.route("/track/attachment/<token>/open")
def track_attachment_open(token: str):
    target = Target.query.filter_by(token=token).first_or_404()
    if not _is_scanner(request):
        _record(target, "opened")
        _record(target, "attachment_opened")
    return redirect(url_for("tracking.landing", token=target.token))


@bp.route("/landing/<token>")
def landing(token: str):
    target = Target.query.filter_by(token=token).first_or_404()
    if not _is_scanner(request):
        _record(target, "opened")
        _record(target, "clicked")
    if target.campaign.landing_type == "click":
        return redirect(url_for("tracking.training", token=target.token))

    company = target.campaign.landing_company or "Your Organisation"
    if target.campaign.custom_landing_id:
        custom_page = db.session.get(LandingPage, target.campaign.custom_landing_id)
        if custom_page:
            return Response(
                _render_custom_landing(custom_page, target, company),
                mimetype="text/html",
            )

    page = target.campaign.landing_page or "custom"
    tpl = {
        "outlook": "landing_outlook.html",
        "gmail": "landing_gmail.html",
        "custom": "landing_custom.html",
    }.get(page, "landing_custom.html")
    return render_template(tpl, target=target, company=company)


@bp.route("/submit/<token>", methods=["POST"])
@csrf_exempt
def submit(token: str):
    target = Target.query.filter_by(token=token).first_or_404()
    # Honeypot field (`website_url`) must remain empty; bots that auto-fill all inputs are ignored.
    honeypot = request.form.get("website_url", "").strip()
    if not honeypot and not _is_scanner(request):
        # IMPORTANT: We intentionally do NOT read request.form["password"].
        # The submitted credentials are discarded on arrival; only the event is logged.
        _record(target, "submitted")
        send_webhook(
            "target.submitted",
            f"Target {target.email} submitted credentials in campaign '{target.campaign.name}'.",
            {"campaign_id": target.campaign_id, "target_email": target.email},
        )
    return redirect(url_for("tracking.training", token=target.token))


@bp.route("/report/<token>")
def report(token: str):
    """Target clicked the 'Report this email as phishing' link — the positive outcome."""
    target = Target.query.filter_by(token=token).first_or_404()
    if not _is_scanner(request):
        _record(target, "reported")
        send_webhook(
            "target.reported",
            f"Target {target.email} reported phishing email in campaign '{target.campaign.name}'.",
            {"campaign_id": target.campaign_id, "target_email": target.email},
        )
    return render_template("reported.html")


@bp.route("/training")
@bp.route("/training/<token>")
def training(token: str | None = None):
    target = Target.query.filter_by(token=token).first() if token else None
    campaign = target.campaign if target else None
    red_flags = _campaign_red_flags(campaign)
    return render_template(
        "training.html",
        target=target,
        campaign=campaign,
        red_flags=red_flags,
    )
