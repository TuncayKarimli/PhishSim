"""Background scheduler: runs every 30s to process scheduled/drip campaigns and repeat-offender follow-ups.

Uses an OS file lock (`instance/scheduler.lock`) so that when running under
multi-worker Gunicorn, only a single process runs the background scheduler.
"""
from datetime import timedelta
import os
import sys
from pathlib import Path

if sys.platform != "win32":
    import fcntl
else:
    fcntl = None

from apscheduler.schedulers.background import BackgroundScheduler

from .audit import log_audit, send_webhook
from .extensions import db
from .mailer import send_campaign, send_next_batch
from .models import Campaign, Target, now_utc

_scheduler = None
_lock_file = None

FOLLOWUP_BODY = """\
<p>Hi {{name}},</p>
<p>This is an automated security verification check from the Information Security team.
Please review and confirm your workstation security settings:</p>
<p><a href="{{link}}">Verify Security Settings</a></p>
<p>Information Security</p>
"""


def _tick(app):
    with app.app_context():
        now = now_utc()
        due = Campaign.query.filter(Campaign.status.in_(("scheduled", "sending"))).all()
        for c in due:
            if c.scheduled_at and c.scheduled_at > now:
                continue
            if c.status == "sending" and c.batch_size > 0 and c.last_batch_at:
                next_at = c.last_batch_at + timedelta(minutes=max(1, c.batch_interval))
                if next_at > now:
                    continue
            send_next_batch(c)

        check_repeat_offenders(app, now=now)


def check_repeat_offenders(app, now=None) -> Campaign | None:
    """Identify targets who submitted credentials in 2+ consecutive campaigns and
    auto-enroll them in a follow-up campaign 14 days after their latest failure.
    """
    with app.app_context():
        now = now or now_utc()
        threshold_days = int(app.config.get("REPEAT_OFFENDER_DAYS", 14))
        cutoff = now - timedelta(days=threshold_days)

        # Group all targets by email ordered chronologically by campaign creation / id
        all_targets = (
            Target.query.join(Campaign, Target.campaign_id == Campaign.id)
            .order_by(Campaign.created_at.asc(), Campaign.id.asc(), Target.id.asc())
            .all()
        )

        by_email: dict[str, list[Target]] = {}
        for t in all_targets:
            by_email.setdefault(t.email.lower(), []).append(t)

        qualifying_targets: list[Target] = []
        for email, history in by_email.items():
            if len(history) < 2:
                continue
            last_two = history[-2:]
            # Both of the last two campaigns must have a 'submitted' event
            if all("submitted" in t.types for t in last_two):
                latest_target = last_two[-1]
                if latest_target.followup_enrolled:
                    continue
                submit_events = [
                    e.timestamp
                    for e in latest_target.events
                    if e.event_type == "submitted" and e.timestamp
                ]
                latest_submit_at = max(submit_events) if submit_events else None
                if latest_submit_at and latest_submit_at <= cutoff:
                    qualifying_targets.append(latest_target)

        if not qualifying_targets:
            return None

        followup_campaign = Campaign(
            name=f"Auto Follow-Up — Repeat Offenders ({now.strftime('%Y-%m-%d')})",
            sender="Information Security <secops@example.com>",
            difficulty="medium",
            subject="Action required: mandatory security verification",
            email_body=FOLLOWUP_BODY,
            landing_type="credentials",
            landing_page="custom",
            landing_company="Security Operations",
            status="scheduled",
            scheduled_at=now,
            is_followup=True,
        )
        db.session.add(followup_campaign)
        db.session.flush()

        for src_t in qualifying_targets:
            src_t.followup_enrolled = True
            db.session.add(
                Target(
                    campaign_id=followup_campaign.id,
                    email=src_t.email,
                    first_name=src_t.first_name,
                    last_name=src_t.last_name,
                    department=src_t.department,
                    location=src_t.location,
                    business_unit=src_t.business_unit,
                )
            )

        db.session.commit()
        send_campaign(followup_campaign)
        log_audit(
            "automation.repeat_offender_campaign",
            f"Created & queued follow-up campaign #{followup_campaign.id} for {len(qualifying_targets)} repeat offender(s)",
            user_email="system",
        )
        send_webhook(
            "automation.repeat_offender",
            f"Auto-enrolled {len(qualifying_targets)} repeat offender(s) in campaign '{followup_campaign.name}'.",
            {"campaign_id": followup_campaign.id, "count": len(qualifying_targets)},
        )
        return followup_campaign


def start_scheduler(app):
    """Start the background scheduler once per host using a non-blocking file lock."""
    global _scheduler, _lock_file
    if _scheduler is not None:
        return _scheduler

    lock_dir = Path(app.instance_path)
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / "scheduler.lock"

    try:
        f = open(lock_path, "w")
        if fcntl is not None:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        f.write(str(os.getpid()))
        f.flush()
        _lock_file = f
    except OSError:
        return None

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(lambda: _tick(app), "interval", seconds=30, id="campaign_sender")
    _scheduler.start()
    return _scheduler
