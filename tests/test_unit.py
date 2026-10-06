"""Comprehensive unit & integration tests for PhishSim v3.0.

Can be run with either:
    pytest
or:
    python -m unittest discover -s tests
"""
from datetime import timedelta
import io
import unittest

from app.extensions import db
from app.mailer import _build_message, generate_qr_base64_png
from app.models import Campaign, Event, LandingPage, SMTPProfile, Target, User, now_utc
from app.scheduler import check_repeat_offenders
from app.security import generate_totp_secret, get_current_totp_code, login_limiter, verify_totp_code
from tests.conftest import make_test_app


class PhishSimUnitTestSuite(unittest.TestCase):
    def setUp(self):
        self.app = make_test_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _login_as_admin(self) -> str:
        admin = User.query.filter_by(email="admin@example.com").first()
        csrf_tok = "csrf-test-token-123"
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(admin.id)
            sess["_csrf_token"] = csrf_tok
        return csrf_tok

    def _create_sample_campaign(self, **kwargs) -> tuple[Campaign, Target]:
        defaults = dict(
            name="Unit Test Campaign",
            sender="IT <it@example.com>",
            difficulty="medium",
            subject="Verify your account",
            email_body='<p>Hello {{name}}, <a href="{{link}}">Click</a> {{qr_code}}</p>',
            landing_type="credentials",
            landing_page="outlook",
            attachment_type="html",
            attachment_name="Notice.html",
        )
        defaults.update(kwargs)
        c = Campaign(**defaults)
        db.session.add(c)
        db.session.flush()
        t = Target(
            campaign_id=c.id,
            email="alex@example.com",
            first_name="Alex",
            last_name="Rivera",
            department="Finance",
            location="London",
            business_unit="Corporate",
        )
        db.session.add(t)
        db.session.commit()
        return c, t

    # ------------------------------------------------------------------
    # 1. Funnel State Transitions & Zero-Password Storage Guarantee
    # ------------------------------------------------------------------
    def test_funnel_state_transitions_and_zero_password_storage(self):
        c, t = self._create_sample_campaign()
        self.assertEqual(t.status, "pending")

        # Sent
        db.session.add(Event(target_id=t.id, event_type="sent"))
        db.session.commit()
        self.assertEqual(t.status, "sent")

        # Open tracking pixel
        r_open = self.client.get(
            f"/track/open/{t.token}.png",
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)"},
        )
        self.assertEqual(r_open.status_code, 200)
        self.assertEqual(t.status, "opened")

        # Attachment open tracking
        r_att = self.client.get(
            f"/track/attachment/{t.token}/open",
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)"},
        )
        self.assertEqual(r_att.status_code, 302)
        self.assertTrue(t.attachment_opened)

        # Landing click
        r_click = self.client.get(
            f"/landing/{t.token}",
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)"},
        )
        self.assertEqual(r_click.status_code, 200)
        self.assertEqual(t.status, "clicked")

        # Credential submission — verify password is NEVER stored anywhere
        secret_pw = "SuperSecretEmployeePassword!999"
        r_sub = self.client.post(
            f"/submit/{t.token}",
            data={"email": t.email, "password": secret_pw, "website_url": ""},
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)"},
        )
        self.assertEqual(r_sub.status_code, 302)
        self.assertIn(f"/training/{t.token}", r_sub.headers["Location"])
        self.assertEqual(t.status, "submitted")

        for ev in Event.query.all():
            self.assertNotIn(secret_pw, ev.event_type or "")
            self.assertNotIn(secret_pw, ev.ip or "")
            self.assertNotIn(secret_pw, ev.user_agent or "")

        # Reporting phishing
        r_rep = self.client.get(
            f"/report/{t.token}",
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)"},
        )
        self.assertEqual(r_rep.status_code, 200)
        self.assertTrue(t.reported)

    # ------------------------------------------------------------------
    # 2. Scanner, Prefetcher & Honeypot Filtering
    # ------------------------------------------------------------------
    def test_scanner_and_honeypot_filtering(self):
        _, t = self._create_sample_campaign()

        # Proofpoint / Mimecast / curl scanners should be ignored
        self.client.get(
            f"/track/open/{t.token}.png",
            headers={"User-Agent": "Proofpoint URL Defense Bot/1.0"},
        )
        self.client.get(
            f"/landing/{t.token}",
            headers={"User-Agent": "Mozilla/5.0", "X-Purpose": "preview"},
        )
        self.assertEqual(t.status, "pending")

        # Honeypot filled by bot on POST /submit/<token> must be ignored
        self.client.post(
            f"/submit/{t.token}",
            data={"email": t.email, "password": "botpw", "website_url": "http://spambot.example"},
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"},
        )
        self.assertNotIn("submitted", t.types)

    # ------------------------------------------------------------------
    # 3. Synchronizer Token CSRF Validation
    # ------------------------------------------------------------------
    def test_csrf_validation_blocks_missing_token_and_allows_valid_token(self):
        csrf_tok = self._login_as_admin()

        # POST without CSRF token -> 400 Bad Request
        r_bad = self.client.post(
            "/smtp-profiles/add",
            data={"name": "Bad Relay", "host": "smtp.bad.local", "port": "25"},
        )
        self.assertEqual(r_bad.status_code, 400)

        # POST with valid CSRF token -> 302 Redirect & created
        r_ok = self.client.post(
            "/smtp-profiles/add",
            data={
                "csrf_token": csrf_tok,
                "name": "Corp Relay",
                "host": "smtp.corp.local",
                "port": "587",
                "use_tls": "on",
            },
        )
        self.assertEqual(r_ok.status_code, 302)
        self.assertIsNotNone(SMTPProfile.query.filter_by(name="Corp Relay").first())

    # ------------------------------------------------------------------
    # 4. Brute-Force Login Rate Limiting
    # ------------------------------------------------------------------
    def test_login_rate_limiting(self):
        login_limiter.clear_all()
        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "login-csrf"

        # 3 failed attempts allowed (LOGIN_RATE_LIMIT=3 in test config)
        for _ in range(3):
            r = self.client.post(
                "/login",
                data={"csrf_token": "login-csrf", "email": "admin@example.com", "password": "wrong"},
            )
            self.assertEqual(r.status_code, 200)

        # 4th attempt within window -> 429 Too Many Requests
        r_blocked = self.client.post(
            "/login",
            data={"csrf_token": "login-csrf", "email": "admin@example.com", "password": "wrong"},
        )
        self.assertEqual(r_blocked.status_code, 429)

    # ------------------------------------------------------------------
    # 5. TOTP 2FA & Enterprise SSO Flows
    # ------------------------------------------------------------------
    def test_totp_2fa_and_sso_flows(self):
        secret = generate_totp_secret()
        code = get_current_totp_code(secret)
        self.assertTrue(verify_totp_code(secret, code))
        self.assertFalse(verify_totp_code(secret, "000000"))

        admin = User.query.filter_by(email="admin@example.com").first()
        admin.totp_secret = secret
        admin.totp_enabled = True
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess["_csrf_token"] = "2fa-csrf"

        # Valid password redirects to /login/2fa
        r_login = self.client.post(
            "/login",
            data={
                "csrf_token": "2fa-csrf",
                "email": "admin@example.com",
                "password": "AdminTestPassword123!",
            },
        )
        self.assertEqual(r_login.status_code, 302)
        self.assertIn("/login/2fa", r_login.headers["Location"])

        # Completing /login/2fa with valid 6-digit code logs the user in
        r_2fa = self.client.post(
            "/login/2fa",
            data={"csrf_token": "2fa-csrf", "totp_code": code},
        )
        self.assertEqual(r_2fa.status_code, 302)
        self.assertEqual(r_2fa.headers["Location"], "/")

        # Enterprise SSO redirect & callback provisioning
        r_sso = self.client.get("/auth/sso/entra")
        self.assertEqual(r_sso.status_code, 302)
        with self.client.session_transaction() as sess:
            sso_state = sess.get("sso_state")
        r_cb = self.client.get(
            f"/auth/sso/entra/callback?state={sso_state}&mock_email=sso.user@example.com&mock_sub=entra-123"
        )
        self.assertEqual(r_cb.status_code, 302)
        sso_user = User.query.filter_by(email="sso.user@example.com").first()
        self.assertIsNotNone(sso_user)
        self.assertEqual(sso_user.sso_provider, "entra")

    # ------------------------------------------------------------------
    # 6. Department Scoping CSV Import & People Risk Aggregation
    # ------------------------------------------------------------------
    def test_department_scoping_csv_import_and_people_aggregation(self):
        csrf_tok = self._login_as_admin()
        csv_content = (
            "email,first_name,last_name,department,location,business_unit\n"
            "alice@example.com,Alice,Wong,Finance,London,Corporate\n"
            "bob@example.com,Bob,Smith,Engineering,Berlin,Product\n"
        )
        r = self.client.post(
            "/campaigns/new",
            data={
                "csrf_token": csrf_tok,
                "name": "Scoped Campaign",
                "sender": "IT <it@example.com>",
                "difficulty": "hard",
                "subject": "Scoped Test",
                "email_body": '<p><a href="{{link}}">Link</a></p>',
                "landing_type": "credentials",
                "landing_page": "custom",
                "csv_file": (io.BytesIO(csv_content.encode("utf-8")), "targets.csv"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(r.status_code, 302)
        alice = Target.query.filter_by(email="alice@example.com").first()
        self.assertIsNotNone(alice)
        self.assertEqual(alice.department, "Finance")
        self.assertEqual(alice.location, "London")
        self.assertEqual(alice.business_unit, "Corporate")

        # Check People page renders group aggregations
        r_people = self.client.get("/people?department=Finance")
        self.assertEqual(r_people.status_code, 200)
        self.assertIn(b"Finance", r_people.data)
        self.assertIn(b"London", r_people.data)

    # ------------------------------------------------------------------
    # 7. Custom Landing Pages, Quishing ({{qr_code}}), & Attachments
    # ------------------------------------------------------------------
    def test_custom_landing_page_quishing_and_attachments(self):
        csrf_tok = self._login_as_admin()

        # Create a custom landing page via POST /landing-pages/add
        r_lp = self.client.post(
            "/landing-pages/add",
            data={
                "csrf_token": csrf_tok,
                "name": "Custom Intranet Login",
                "html_body": '<form method="post" action="{{submit_url}}"><h1>{{company}}</h1><input name="email" value="{{email}}"></form>',
            },
        )
        self.assertEqual(r_lp.status_code, 302)
        lp = LandingPage.query.filter_by(name="Custom Intranet Login").first()
        self.assertIsNotNone(lp)

        c, t = self._create_sample_campaign(
            landing_page="custom_template",
            custom_landing_id=lp.id,
            landing_company="Globex Corp",
            attachment_type="pdf",
            attachment_name="Report.pdf",
        )

        # Verify landing route renders the dynamic custom landing page + injects honeypot
        r_land = self.client.get(f"/landing/{t.token}", headers={"User-Agent": "Mozilla/5.0"})
        self.assertEqual(r_land.status_code, 200)
        self.assertIn(b"Globex Corp", r_land.data)
        self.assertIn(b"alex@example.com", r_land.data)
        self.assertIn(b"website_url", r_land.data)

        # Verify MIME message builder embeds inline base64 PNG QR code and PDF attachment
        msg = _build_message(c, t, "http://localhost:5000")
        raw_email = msg.as_string()
        html_part = msg.get_payload()[0].get_payload()[1].get_payload(decode=True).decode("utf-8")
        self.assertIn("data:image/png;base64,", html_part)
        self.assertIn("Report.pdf", raw_email)
        self.assertTrue(len(generate_qr_base64_png("http://localhost:5000/landing/test")) > 50)

    # ------------------------------------------------------------------
    # 8. Time-Series Analytics & Repeat-Offender Automation
    # ------------------------------------------------------------------
    def test_timeseries_analytics_and_repeat_offender_automation(self):
        self._login_as_admin()
        now = now_utc()
        old_time = now - timedelta(days=16)

        c1, t1 = self._create_sample_campaign(name="Camp 1")
        c2 = Campaign(
            name="Camp 2",
            sender="IT <it@example.com>",
            difficulty="medium",
            subject="Check 2",
            email_body='<p><a href="{{link}}">Click</a></p>',
        )
        db.session.add(c2)
        db.session.flush()
        t2 = Target(
            campaign_id=c2.id,
            email=t1.email,
            first_name=t1.first_name,
            last_name=t1.last_name,
            department="Finance",
        )
        db.session.add(t2)
        db.session.flush()

        # Record 'submitted' in both consecutive campaigns, with latest 16 days ago (>= 14d threshold)
        db.session.add(Event(target_id=t1.id, event_type="submitted", timestamp=old_time - timedelta(days=5)))
        db.session.add(Event(target_id=t2.id, event_type="submitted", timestamp=old_time))
        db.session.commit()

        # Run repeat-offender job
        followup = check_repeat_offenders(self.app, now=now)
        self.assertIsNotNone(followup)
        self.assertTrue(followup.is_followup)
        self.assertEqual(len(followup.targets), 1)
        self.assertEqual(followup.targets[0].email, "alex@example.com")

        # Re-running immediately should not duplicate follow-up enrollment
        self.assertIsNone(check_repeat_offenders(self.app, now=now))

        # Verify Time-Series JSON API
        r_ts = self.client.get("/api/analytics/timeseries")
        self.assertEqual(r_ts.status_code, 200)
        data = r_ts.get_json()
        self.assertIn("monthly", data)
        self.assertIn("quarterly", data)
        self.assertGreaterEqual(len(data["monthly"]), 1)


if __name__ == "__main__":
    unittest.main()
