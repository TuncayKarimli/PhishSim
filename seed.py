"""Optional: create a demo campaign with scoped targets and sample activity so you can explore immediately.

    python seed.py
"""
from app import create_app
from app.extensions import db
from app.models import AuditLog, Campaign, Event, SMTPProfile, Target

app = create_app()

BODY = """\
<p>Hi {{name}},</p>
<p>Our IT team detected unusual sign-in activity on your account. Please confirm
your identity within 24 hours to keep your access active:</p>
<p><a href="{{link}}">Verify my account</a></p>
<p>IT Support</p>
"""

with app.app_context():
    default_smtp = SMTPProfile.query.filter_by(is_default=True).first()
    campaign = Campaign(
        name="Demo — Account Verification",
        sender="IT Support <it-support@example.com>",
        difficulty="medium",
        subject="Action required: confirm your account",
        email_body=BODY,
        landing_type="credentials",
        landing_page="outlook",
        smtp_profile_id=default_smtp.id if default_smtp else None,
        attachment_type="pdf",
        attachment_name="Account_Security_Notice.pdf",
        status="sent",
    )
    db.session.add(campaign)
    db.session.flush()

    demo_targets = [
        ("Alex", "Rivera", "alex@example.com", "Finance", "London", "Corporate", ["sent", "opened", "attachment_opened", "clicked", "submitted"]),
        ("Sam", "Okafor", "sam@example.com", "Engineering", "New York", "Product", ["sent", "opened", "clicked"]),
        ("Jordan", "Lee", "jordan@example.com", "Security", "London", "Platform", ["sent", "opened", "reported"]),
        ("Priya", "Shah", "priya@example.com", "Finance", "Singapore", "Corporate", ["sent", "opened"]),
    ]

    for first, last, email, dept, loc, bu, events in demo_targets:
        t = Target(
            campaign_id=campaign.id,
            email=email,
            first_name=first,
            last_name=last,
            department=dept,
            location=loc,
            business_unit=bu,
        )
        db.session.add(t)
        db.session.flush()
        for ev in events:
            db.session.add(
                Event(
                    target_id=t.id,
                    event_type=ev,
                    ip="127.0.0.1",
                    user_agent="Mozilla/5.0 (Demo Seed)",
                )
            )

    db.session.add(
        AuditLog(
            user_email="admin@example.com",
            action="campaign.seeded",
            details=f"Seeded demo campaign #{campaign.id} ({campaign.name}) with 4 department-scoped targets",
            ip="127.0.0.1",
        )
    )

    db.session.commit()
    print(f"Created demo campaign #{campaign.id} with 4 department-scoped targets and sample events.")
