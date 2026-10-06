"""Built-in starter email templates, custom landing pages, and default SMTP profile."""
from .models import LandingPage, SMTPProfile, Template

DEFAULTS = [
    (
        "Prize / Gift Card (easy)",
        "easy",
        "URGENT: You won a $500 gift card!! Claim NOW!",
        "<p>Dear user,</p>"
        "<p>Congratulations!! You have been randomly selected to receive a "
        "<b>$500 Amazon gift card</b>. Click below in the next 15 MINUTES or it expires!</p>"
        '<p><a href="{{link}}">CLAIM YOUR PRIZE NOW</a></p>'
        "<p>Thanks,<br>The Rewards Department</p>",
    ),
    (
        "Free Coffee Voucher (easy)",
        "easy",
        "Free coffee voucher for all staff today ☕",
        "<p>Hey {{name}},</p>"
        "<p>Management is giving everyone a free coffee voucher this week! "
        "Grab yours before they run out:</p>"
        '<p><a href="{{link}}">Download my voucher</a></p>',
    ),
    (
        "Password Expiry (medium)",
        "medium",
        "Action required: your password expires in 24 hours",
        "<p>Hi {{name}},</p>"
        "<p>Your corporate password is set to expire in <b>24 hours</b>. "
        "To avoid being locked out of email and VPN, keep your current password here:</p>"
        '<p><a href="{{link}}">Keep my current password</a></p>'
        "<p>IT Helpdesk</p>",
    ),
    (
        "Shared Document (medium)",
        "medium",
        "Alex shared 'Q3 Compensation Review.xlsx' with you",
        "<p>Hi {{name}},</p>"
        "<p>A document has been shared with you and requires your sign-in to view:</p>"
        '<p><a href="{{link}}">Open Q3 Compensation Review.xlsx</a></p>'
        "<p style='color:#64748b;font-size:12px'>OneDrive for Business</p>",
    ),
    (
        "Delivery Held (medium)",
        "medium",
        "Delivery attempt failed — confirm your address",
        "<p>Hi {{name}},</p>"
        "<p>We couldn't deliver a package addressed to you at the office today. "
        "Please confirm your desk/building so we can re-attempt tomorrow:</p>"
        '<p><a href="{{link}}">Confirm delivery details</a></p>',
    ),
    (
        "HR Benefits Acknowledgement (hard)",
        "hard",
        "HR: Updated remote-work & benefits policy — please acknowledge by Friday",
        "<p>Hi {{name}},</p>"
        "<p>Following yesterday's all-hands, the updated remote-work and benefits "
        "addendum is ready for review. Please sign in with your work account and "
        "acknowledge by Friday EOD so HR can close the audit log:</p>"
        '<p><a href="{{link}}">Review &amp; acknowledge policy</a></p>'
        "<p>Thanks,<br>People Operations</p>",
    ),
    (
        "IT Security MFA Check (hard)",
        "hard",
        "Security notice: new sign-in from unrecognized device",
        "<p>Hi {{name}},</p>"
        "<p>We noticed a sign-in to your account from a new browser. If this was you, "
        "no action is needed. If you don't recognise this activity, review your session now:</p>"
        '<p><a href="{{link}}">Review recent activity</a></p>'
        "<p>Security Operations</p>",
    ),
    (
        "MFA QR Code Re-Enrollment (Quishing)",
        "hard",
        "IT Security: Mandatory Authenticator QR Re-Sync",
        "<p>Hi {{name}},</p>"
        "<p>As part of our quarterly zero-trust upgrade, all employees must re-sync "
        "their mobile authenticator device within 24 hours.</p>"
        "<p>Scan the secure QR code below with your phone camera or click the fallback link:</p>"
        "<div style='margin:16px 0;'>{{qr_code}}</div>"
        '<p><a href="{{link}}">Fallback: Verify via Web Portal</a></p>'
        "<p>Identity &amp; Access Management</p>",
    ),
]


DEFAULT_LANDING_PAGES = [
    (
        "Corporate SSO Portal",
        "corporate-sso",
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{company}} · Single Sign-On</title>
  <style>
    body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#0f172a; color:#f8fafc; display:grid; place-items:center; min-height:100vh; }
    .box { background:#1e293b; border:1px solid #334155; border-radius:12px; width:100%; max-width:390px; padding:32px; box-shadow:0 20px 50px rgba(0,0,0,.4); }
    .badge { display:inline-block; background:#2563eb; color:#fff; font-weight:700; font-size:12px; padding:4px 10px; border-radius:999px; margin-bottom:12px; }
    h1 { margin:0 0 6px; font-size:22px; }
    p { margin:0 0 20px; color:#94a3b8; font-size:14px; }
    label { display:block; font-size:13px; font-weight:600; margin-bottom:6px; color:#cbd5e1; }
    input { width:100%; padding:10px 12px; border-radius:8px; border:1px solid #475569; background:#0f172a; color:#fff; margin-bottom:16px; box-sizing:border-box; }
    button { width:100%; padding:11px; border:none; border-radius:8px; background:#2563eb; color:#fff; font-weight:600; font-size:15px; cursor:pointer; }
    button:hover { background:#1d4ed8; }
    .hp { position:absolute; left:-9999px; opacity:0; pointer-events:none; }
  </style>
</head>
<body>
  <div class="box">
    <span class="badge">{{company}} SSO</span>
    <h1>Verify your identity</h1>
    <p>Sign in with your corporate credentials to continue.</p>
    <form method="post" action="{{submit_url}}" autocomplete="off">
      <div class="hp" aria-hidden="true">
        <input type="text" name="website_url" tabindex="-1" autocomplete="off">
      </div>
      <label>Work Email</label>
      <input type="email" name="email" value="{{email}}" required>
      <label>Password</label>
      <input type="password" name="password" required autofocus>
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>""",
    ),
    (
        "IT VPN Re-Authentication",
        "vpn-reauth",
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>GlobalProtect VPN · Re-Authentication</title>
  <style>
    body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:#f1f5f9; color:#0f172a; display:grid; place-items:center; min-height:100vh; }
    .card { background:#fff; border:1px solid #cbd5e1; border-top:4px solid #dc2626; border-radius:8px; width:100%; max-width:380px; padding:28px; box-shadow:0 4px 16px rgba(15,23,42,.08); }
    h2 { margin:0 0 6px; font-size:20px; }
    p { margin:0 0 18px; color:#64748b; font-size:13px; }
    label { display:block; font-size:12px; font-weight:700; text-transform:uppercase; margin-bottom:5px; color:#475569; }
    input { width:100%; padding:9px 11px; border:1px solid #cbd5e1; border-radius:6px; margin-bottom:14px; box-sizing:border-box; }
    button { width:100%; padding:10px; border:none; border-radius:6px; background:#0f172a; color:#fff; font-weight:600; cursor:pointer; }
    .hp { position:absolute; left:-9999px; opacity:0; pointer-events:none; }
  </style>
</head>
<body>
  <div class="card">
    <h2>VPN Session Expired</h2>
    <p>Please re-enter your network credentials to restore remote access.</p>
    <form method="post" action="{{submit_url}}" autocomplete="off">
      <div class="hp" aria-hidden="true">
        <input type="text" name="website_url" tabindex="-1" autocomplete="off">
      </div>
      <label>Username / Email</label>
      <input type="text" name="email" value="{{email}}" required>
      <label>Network Password</label>
      <input type="password" name="password" required autofocus>
      <button type="submit">Reconnect VPN</button>
    </form>
  </div>
</body>
</html>""",
    ),
]


def seed_default_templates(db):
    existing_names = {t.name for t in Template.query.all()}
    added = False
    for name, diff, subj, body in DEFAULTS:
        if name not in existing_names:
            db.session.add(Template(name=name, difficulty=diff, subject=subj, body=body))
            added = True
    if added:
        db.session.commit()


def seed_default_landing_pages(db):
    existing_slugs = {p.slug for p in LandingPage.query.all()}
    added = False
    for name, slug, html_body in DEFAULT_LANDING_PAGES:
        if slug not in existing_slugs:
            db.session.add(LandingPage(name=name, slug=slug, html_body=html_body))
            added = True
    if added:
        db.session.commit()


def seed_default_smtp_profile(db, app):
    if SMTPProfile.query.count() > 0:
        return
    profile = SMTPProfile(
        name="Default SMTP (from .env)",
        host=app.config.get("SMTP_HOST", "localhost"),
        port=int(app.config.get("SMTP_PORT", 1025)),
        username=app.config.get("SMTP_USER", ""),
        password=app.config.get("SMTP_PASSWORD", ""),
        use_tls=bool(app.config.get("SMTP_USE_TLS", False)),
        from_address="IT Support <it-support@example.com>",
        is_default=True,
    )
    db.session.add(profile)
    db.session.commit()
