"""Database models: User, SMTPProfile, LandingPage, Campaign, Target, Event, Template, AuditLog.

Privacy note: Event NEVER stores any form input or credentials — only the
event type, timestamp, IP, and User-Agent string.
"""
from datetime import datetime, timezone
import secrets
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db, login_manager

# Funnel stages in order. "reported" is tracked separately because reporting a
# phish is the GOOD outcome, not a deeper failure stage.
FUNNEL = ("sent", "opened", "clicked", "submitted")
FUNNEL_ORDER = {stage: i for i, stage in enumerate(FUNNEL)}


def now_utc() -> datetime:
    """Return a timezone-naive UTC datetime for consistent SQLite storage & comparison."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _new_token() -> str:
    return secrets.token_urlsafe(24)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False, default="")
    # "admin" can create/send/delete; "viewer" is read-only.
    role = db.Column(db.String(20), nullable=False, default="admin")

    # Enterprise SSO (Entra ID, Google Workspace, Okta)
    sso_provider = db.Column(db.String(40), default="")
    sso_subject = db.Column(db.String(255), default="")

    # Optional TOTP 2FA for local accounts
    totp_secret = db.Column(db.String(64), default="")
    totp_enabled = db.Column(db.Boolean, default=False)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def _load_user(user_id: str):
    return db.session.get(User, int(user_id))


class SMTPProfile(db.Model):
    """Reusable SMTP sending profile selectable per campaign."""
    __tablename__ = "smtp_profiles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    host = db.Column(db.String(255), nullable=False, default="localhost")
    port = db.Column(db.Integer, nullable=False, default=1025)
    username = db.Column(db.String(255), default="")
    password = db.Column(db.String(255), default="")
    use_tls = db.Column(db.Boolean, default=False)
    from_address = db.Column(db.String(255), default="IT Support <it-support@example.com>")
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class LandingPage(db.Model):
    """Custom HTML landing page editable in the web UI."""
    __tablename__ = "landing_pages"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    html_body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class Campaign(db.Model):
    __tablename__ = "campaigns"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    sender = db.Column(db.String(255), nullable=False, default="IT Support <no-reply@example.com>")
    difficulty = db.Column(db.String(20), nullable=False, default="medium")  # easy / medium / hard
    subject = db.Column(db.String(255), nullable=False)
    email_body = db.Column(db.Text, nullable=False)  # HTML; supports {{name}}, {{link}}, {{report_link}}, {{qr_code}}
    # "credentials" -> show login page; "click" -> go straight to training on click.
    landing_type = db.Column(db.String(20), nullable=False, default="credentials")
    # Which login page to show: "outlook", "gmail", "custom", or "custom_template"
    landing_page = db.Column(db.String(30), nullable=False, default="custom")
    landing_company = db.Column(db.String(255), default="")

    # Optional foreign keys for SMTP Profile and Custom Landing Page
    smtp_profile_id = db.Column(db.Integer, db.ForeignKey("smtp_profiles.id"), nullable=True)
    custom_landing_id = db.Column(db.Integer, db.ForeignKey("landing_pages.id"), nullable=True)

    # Attachment simulation ("none", "html", "pdf")
    attachment_type = db.Column(db.String(20), default="none")
    attachment_name = db.Column(db.String(255), default="")

    # Scheduling & drip-sending
    status = db.Column(db.String(20), nullable=False, default="draft")  # draft / scheduled / sending / sent
    scheduled_at = db.Column(db.DateTime, nullable=True)
    batch_size = db.Column(db.Integer, nullable=False, default=0)       # 0 = send all at once
    batch_interval = db.Column(db.Integer, nullable=False, default=0)   # minutes between batches
    last_batch_at = db.Column(db.DateTime, nullable=True)
    is_followup = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_utc)

    smtp_profile = db.relationship("SMTPProfile", backref="campaigns", lazy="joined")
    custom_landing = db.relationship("LandingPage", backref="campaigns", lazy="joined")

    targets = db.relationship(
        "Target", backref="campaign", cascade="all, delete-orphan", lazy="selectin"
    )

    def stats(self) -> dict:
        """Distinct targets that reached each stage + reported + attachment_opened counts."""
        total = len(self.targets)
        counts = {stage: 0 for stage in FUNNEL}
        counts["reported"] = 0
        counts["attachment_opened"] = 0
        for t in self.targets:
            reached = t.types
            for stage in FUNNEL:
                if stage in reached:
                    counts[stage] += 1
            if "reported" in reached:
                counts["reported"] += 1
            if "attachment_opened" in reached:
                counts["attachment_opened"] += 1
        pct = {
            k: round((v / total) * 100, 1) if total else 0.0
            for k, v in counts.items()
        }
        return {"total": total, **counts, "pct": pct}


class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(120), default="")
    last_name = db.Column(db.String(120), default="")
    department = db.Column(db.String(120), default="")
    location = db.Column(db.String(120), default="")
    business_unit = db.Column(db.String(120), default="")
    followup_enrolled = db.Column(db.Boolean, default=False)
    token = db.Column(db.String(64), unique=True, nullable=False, default=_new_token)

    events = db.relationship(
        "Event", backref="target", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip() or self.email

    @property
    def types(self) -> set:
        return {e.event_type for e in self.events}

    @property
    def status(self) -> str:
        """Furthest RISKY funnel stage this target reached."""
        risky = self.types & set(FUNNEL_ORDER)
        if not risky:
            return "pending"
        return max(risky, key=lambda t: FUNNEL_ORDER[t])

    @property
    def reported(self) -> bool:
        return "reported" in self.types

    @property
    def attachment_opened(self) -> bool:
        return "attachment_opened" in self.types

    @property
    def last_event_at(self):
        """Timestamp of the most recent interaction (excluding 'sent'), or None."""
        interactions = [e.timestamp for e in self.events if e.event_type != "sent" and e.timestamp]
        return max(interactions) if interactions else None


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    event_type = db.Column(db.String(30), nullable=False)  # sent/opened/clicked/submitted/reported/attachment_opened
    timestamp = db.Column(db.DateTime, default=now_utc)
    ip = db.Column(db.String(64), default="")
    user_agent = db.Column(db.String(255), default="")


class Template(db.Model):
    """A reusable email template. Every body should contain {{link}} or {{qr_code}}."""
    __tablename__ = "templates"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    difficulty = db.Column(db.String(20), default="medium")
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)  # HTML with {{name}}, {{link}}, {{qr_code}}
    created_at = db.Column(db.DateTime, default=now_utc)


class AuditLog(db.Model):
    """Immutable log of admin and security actions."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(255), default="system")
    action = db.Column(db.String(80), nullable=False)
    details = db.Column(db.Text, default="")
    ip = db.Column(db.String(64), default="")
    created_at = db.Column(db.DateTime, default=now_utc)
