# PhishSim — Project Overview & Architecture (v3.0 Enterprise Release)

> **Current Version:** `v3.0` (Enterprise Auth, Advanced Simulations, Analytics & Automated Testing)  
> **Stack:** Python 3.12+, Flask 3, SQLAlchemy 2, Flask-Migrate (Alembic), Authlib, PyOTP, QRCode, APScheduler, ReportLab, Gunicorn, Docker Compose, Pytest / Playwright

---

## 1. Executive Summary

**PhishSim v3.0** is a self-hosted, enterprise-grade security awareness and phishing simulation platform. It enables organisations to send authorised simulated phishing emails (including **QR-code "Quishing"** and **tracked HTML/PDF attachments**) via **multiple SMTP sending profiles**, measure the conversion funnel (`sent → opened → attachment_opened → clicked → submitted`), positively reinforce employees who **report** suspicious emails (`reported`), compare risk across **Departments, Locations, and Business Units**, visualize **Month-over-Month & Quarter-over-Quarter trends**, and automatically enroll **repeat offenders** into follow-up campaigns.

> [!IMPORTANT]
> **Zero-Password Storage Guarantee:** When an employee submits a simulated login page, PhishSim records only that a `submitted` event occurred (timestamp, IP, User-Agent) and immediately discards the form payload. No password is ever read, logged, hashed, or stored.

---

## 2. Architecture & Complete File Map

| File | Role |
|---|---|
| [run.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/run.py) | Local development entrypoint (`python run.py`) |
| [wsgi.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/wsgi.py) | Production WSGI entrypoint for Gunicorn (`gunicorn wsgi:app`) |
| [worker.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/worker.py) | Standalone background scheduler worker (`python worker.py`) |
| [config.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/config.py) | Environment configuration (SSO providers, repeat-offender threshold, production validation) |
| [seed.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/seed.py) | Demo data seeder (department-scoped targets, attachment & funnel events, audit log) |
| [app/__init__.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/__init__.py) | App factory, `Flask-Migrate`, SSO init, `/health` endpoint, blueprint registration |
| [app/extensions.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/extensions.py) | `SQLAlchemy`, `LoginManager`, and `Migrate` instances |
| [app/security.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/security.py) | CSRF protection, `LoginRateLimiter`, TOTP 2FA (`pyotp`), and Enterprise SSO (`Authlib`) |
| [app/models.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/models.py) | Models: `User`, `SMTPProfile`, `LandingPage`, `Campaign`, `Target`, `Event`, `Template`, `AuditLog` |
| [app/mailer.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/mailer.py) | Multi-profile SMTP sender, `{{qr_code}}` PNG generator, tracked HTML/PDF attachment builder |
| [app/scheduler.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/scheduler.py) | File-locked scheduler for scheduled/drip sends + `check_repeat_offenders` automation |
| [app/routes/auth.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/routes/auth.py) | Local login, `/login/2fa`, `/auth/sso/<provider>`, `/account/password` & 2FA enrollment |
| [app/routes/dashboard.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/routes/dashboard.py) | Campaign CRUD, scoped CSV parser, `/api/analytics/timeseries`, CSV & PDF exports |
| [app/routes/smtp_profiles.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/routes/smtp_profiles.py) | `/smtp-profiles` CRUD, default profile switching, and live SMTP connection testing |
| [app/routes/landing_pages.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/routes/landing_pages.py) | `/landing-pages` CRUD for custom HTML credential-capture pages |
| [app/routes/tracking.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/routes/tracking.py) | Open pixel, attachment beacon/redirect, dynamic landing pages, honeypot, contextual training |
| [app/routes/people.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/app/routes/people.py) | Employee and Department / Location / Business Unit risk aggregation & filtering |
| [migrations/versions/baseline_v3_schema.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/migrations/versions/baseline_v3_schema.py) | Alembic baseline migration for all 8 tables + idempotent column upgrader |
| [tests/test_unit.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/tests/test_unit.py) | Unit & integration tests covering all 10 v3.0 features |
| [tests/test_e2e_playwright.py](file:///Users/aliiskandarli/Documents/Coding/Projects/phishsim/phishsim/tests/test_e2e_playwright.py) | Playwright E2E browser tests for login and campaign creation |

---

## 3. Summary of the 10 Implemented v3.0 Upgrades

1. **SSO & TOTP 2FA Integration**: Microsoft Entra ID, Google Workspace, and Okta OIDC SSO (`/auth/sso/<provider>`) plus TOTP 2FA QR-code enrollment (`/account/password`) and login verification (`/login/2fa`).
2. **Department Scoping**: `Target` tracks `department`, `location`, and `business_unit` via CSV import (`email,first_name,last_name,department,location,business_unit`) with group comparison tables and filters on `/people`.
3. **Multiple SMTP Profiles**: `SMTPProfile` model and `/smtp-profiles` management UI with per-campaign profile selection and live SMTP connection testing.
4. **Custom Landing Page Editor**: `LandingPage` model and `/landing-pages` live side-by-side HTML editor with sandboxed iframe preview and dynamic serving on `/landing/<token>`.
5. **Attachment-Based Simulations**: Generates benign tracked `.html` and `.pdf` attachments containing `/track/attachment/<token>` beacons and logs `attachment_opened` events.
6. **QR-Code Phishing ("Quishing")**: `{{qr_code}}` placeholder dynamically generates an inline `data:image/png;base64,...` QR code pointing to `/landing/<token>`.
7. **Time-Series Analytics**: `/api/analytics/timeseries` backend aggregation and interactive Chart.js / Canvas trend chart on `/` with **Month-over-Month** and **Quarter-over-Quarter** toggles.
8. **Repeat-Offender Automation**: `check_repeat_offenders()` in `app/scheduler.py` detects employees who submitted credentials in 2+ consecutive campaigns and auto-enrolls them into a follow-up campaign 14 days after their latest failure.
9. **Alembic Migrations**: Full `migrations/` setup (`alembic.ini`, `env.py`, `0001_baseline_v3`) replacing the legacy `_ensure_schema` function.
10. **Automated Testing Suite**: `tests/conftest.py`, `tests/test_unit.py`, and `tests/test_e2e_playwright.py`.
