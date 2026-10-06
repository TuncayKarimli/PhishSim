"""Audit logging and optional Slack / generic webhook notifications."""
import json
import threading
import urllib.request

from flask import current_app, has_request_context, request
from flask_login import current_user

from .extensions import db
from .models import AuditLog, now_utc


def log_audit(action: str, details: str = "", user_email: str | None = None) -> None:
    """Record an administrative or security event in the audit_logs table."""
    if user_email is None:
        if has_request_context() and getattr(current_user, "is_authenticated", False):
            user_email = current_user.email
        else:
            user_email = "system"

    ip = (request.remote_addr or "") if has_request_context() else ""
    entry = AuditLog(
        user_email=user_email,
        action=action,
        details=details,
        ip=ip,
        created_at=now_utc(),
    )
    db.session.add(entry)
    db.session.commit()


def _post_webhook(url: str, payload: dict) -> None:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "PhishSim-Webhook/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass


def send_webhook(event: str, text: str, extra: dict | None = None) -> None:
    """Fire-and-forget webhook alert (compatible with Slack, Discord, and SIEM endpoints)."""
    url = (current_app.config.get("WEBHOOK_URL") or "").strip()
    if not url:
        return
    payload = {
        "event": event,
        "text": text,
        "content": text,
        "timestamp": now_utc().isoformat() + "Z",
        "details": extra or {},
    }
    threading.Thread(target=_post_webhook, args=(url, payload), daemon=True).start()
