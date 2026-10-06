# PhishSim — Security Awareness Simulation Platform

A self-hosted, GoPhish-style tool that lets an organisation send simulated
phishing emails to **its own consenting employees**, track the funnel
(sent → opened → clicked → submitted), reward people who **report** the email,
and redirect everyone to a short training page afterwards.

> **Authorised use only.** This is a security-awareness training tool. Only use
> it against recipients who have consented (e.g. your own employees under an
> internal awareness programme).

> **We never store passwords.** When a target submits the fake login form, the
> app records *that a submission happened* and then throws the input away. No
> password is read, logged, hashed, or stored. See `app/routes/tracking.py`.

---

## 1. Features

| Feature | Where |
|---|---|
| Admin login + **role-based access** (admin vs read-only viewer) | `app/routes/auth.py`, `app/security.py`, `app/routes/users.py` |
| Create campaign + import targets (CSV or paste) | `app/routes/dashboard.py` |
| **Difficulty levels** (easy / medium / hard) with starter templates | `app/templates/campaign_new.html` |
| **Scheduled & drip** sending (waves over time) | `app/scheduler.py`, `app/mailer.py` |
| Send tracked emails over SMTP | `app/mailer.py` |
| Open / click / submit / **report** tracking | `app/routes/tracking.py` |
| Funnel dashboard | `app/templates/campaign_detail.html` |
| **Per-employee risk** across all campaigns | `app/routes/people.py` |
| **CSV + PDF export** of results | `app/routes/dashboard.py` |
| Chooseable landing pages — Outlook / Gmail / company-branded custom | `app/templates/landing_*.html` |
| Interactive, dark-themed training page | `app/templates/training.html` |

Two campaign outcomes:
- **Credential entry** — target lands on a login page; submitting is the failure.
- **Link click** — clicking the link is the failure; go straight to training.

---

## 2. Run it (5 steps)

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # then edit if you like
python seed.py                       # optional: demo campaign + targets
python run.py
```

Open **http://localhost:5000** and log in with the admin account from `.env`
(defaults: `admin@example.com` / `admin123` — change these before real use).
The SQLite database and the first admin are created automatically.

> **Upgrading from the first version?** The schema changed. Delete the old
> `phishsim.db` (or `instance/phishsim.db`) once, then start again.

---

## 3. Test that mail is actually going out (MailHog)

MailHog is a tiny fake SMTP server with a web inbox — nothing leaves your machine.

```bash
docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog
# or a binary from https://github.com/mailhog/MailHog/releases
```

SMTP is on port **1025**, web inbox at **http://localhost:8025** — which is what
the default `.env` already points at, so no config change is needed.

**Full loop:**
1. Log in → open the demo campaign → **Send now**.
2. Open **http://localhost:8025** — the emails are there.
3. Click a message's link → land on the fake login → submit → training page.
4. Or click the **“Report it as phishing”** link in the email → “Great catch!”
5. Back in PhishSim, refresh the campaign — the funnel and **Reported** count update.

> No MailHog? On the campaign page each target row has **click ↗** and
> **report ↗** links that simulate those outcomes without sending mail.

### Sending to real inboxes (e.g. Gmail)
Edit `.env`:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-16-char-app-password   # Google account → App Passwords
SMTP_USE_TLS=true
BASE_URL=http://YOUR_LAN_IP:5000          # must be reachable by the recipient
```
`BASE_URL` must be an address the recipient's browser can reach (your LAN IP, or
a tunnel like [ngrok](https://ngrok.com/): `ngrok http 5000`).

---

## 4. Using the new features

**Difficulty & templates** — pick a level on the new-campaign form; the *Load
easy/medium/hard template* chips fill in a starter subject and body.

**Schedule & drip** — expand *Schedule & drip sending*. Set a send time to have
the background scheduler send it automatically. Set a **batch size** and
**interval** to release it in waves (e.g. 50 people every 10 minutes). Leave the
time blank to send manually with **Send now**. (The scheduler runs only under
`python run.py`, polling every 30s.)

**Report phishing** — every simulated email includes a report link. Reporting
records the *good* outcome and shows a thank-you page. In a real deployment,
reporting usually happens via your mail client's “Report phishing” button; the
in-email link here makes it demoable.

**Landing pages** — for credential-entry campaigns, pick the login page targets
see: **Outlook**, **Gmail**, or a **Custom** page branded with a company name you
enter. Choose it on the New Campaign / Edit form.

**People (risk)** — the People page aggregates everyone across all campaigns and
scores them: `submits×3 + clicks×1 − reports×1`, bucketed Low / Medium / High.

**Export** — on any campaign, **Export CSV** or **Export PDF** for a results
report to hand to management.

**Users & roles** — as an admin, open **Users** to add read-only **viewers**
(they can see results but can't create, send, or delete) or more admins.

---

## 5. How tracking works

Each target gets a unique, unguessable `token`. Every link and the pixel embed
it, so events attribute to the right person.

| Event | Triggered by |
|---|---|
| `sent` | a successful SMTP delivery |
| `opened` | the email client loads `/track/open/<token>.png` |
| `clicked` | the target opens `/landing/<token>` |
| `submitted` | the target posts the login form to `/submit/<token>` |
| `reported` | the target opens `/report/<token>` |

The funnel counts **distinct targets** per stage.

**Real-world caveat:** corporate mail scanners and prefetchers sometimes open
tracking URLs automatically, faking "opens". `app/routes/tracking.py` filters a
few known scanner user-agents. Gmail/Outlook also proxy images, so open-tracking
is always approximate — clicks, submits, and reports are the reliable signals.

---

## 6. Project structure

```
phishsim/
├── run.py                 # start here:  python run.py  (also starts the scheduler)
├── config.py              # settings from .env
├── seed.py                # optional demo data
├── requirements.txt
├── .env.example
└── app/
    ├── __init__.py        # app factory
    ├── extensions.py      # db + login manager
    ├── security.py        # admin_required decorator
    ├── scheduler.py       # background sender for scheduled/drip campaigns
    ├── models.py          # User, Campaign, Target, Event
    ├── mailer.py          # builds + sends tracked emails, drip batching
    ├── routes/
    │   ├── auth.py        # login / logout
    │   ├── dashboard.py   # campaigns, stats, send, CSV/PDF export
    │   ├── tracking.py    # pixel, landing, submit, report, training
    │   ├── people.py      # per-employee risk
    │   └── users.py       # user management (admin)
    ├── templates/         # Jinja2 HTML
    └── static/css/        # styles
```

---

## 7. Switching to MySQL (optional)

1. `pip install PyMySQL`
2. `.env`: `DATABASE_URL=mysql+pymysql://user:password@localhost/phishsim`
3. `CREATE DATABASE phishsim;` once. Tables are created on next start.

---

## 8. Ideas for the next iteration

- Email **open-rate** heuristics (timing/interaction) to cut scanner noise further.
- **Webhook/Slack** alert when someone submits credentials.
- A visual **landing-page editor** (edit the login page HTML in the UI).
- Multi-tenant **organisations / teams**.
- Automated **repeat-offender** follow-up campaigns.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| "Could not connect to the mail server" on Send | Is MailHog (or your SMTP host) running and matching `.env`? |
| **Clicking the link in MailHog shows nothing and the click isn't counted** | The request never reached the app. In the MailHog email, check the link's address: (1) it must not contain literal `{{link}}` — write the placeholder as `{{link}}` (spaces/case are now tolerated, e.g. `{{ link }}` works too); (2) that address must be reachable from the browser you click in. The Send confirmation now prints the exact link so you can verify it; the app also points links at the host you're using. |
| Links don't work for recipients | `BASE_URL` must be reachable by *their* browser, not `localhost`. |
| Scheduled campaign didn't send | The scheduler runs only under `python run.py`; check the send time (server local) has passed. |
| Opens not counting | Many clients block images; rely on click/submit/report. |
| 403 on New campaign / Users | You're logged in as a **viewer**; use an admin account. |
| Errors after upgrading | Delete the old `phishsim.db` and restart. |
| Reset everything | Stop the app and delete `phishsim.db`. |
