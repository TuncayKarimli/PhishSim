# PhishSim — Week-Long Demo Deployment Runbook

Goal: a persistent, HTTPS, publicly reachable instance for ~1 week with two live
presentations, sending **real** simulated emails to a **small, consented** list.

> **Scope guardrail.** This is a security-awareness *demo*. Only send to people who
> said yes (classmates + your teacher). Use the **Custom / company-branded** landing
> page (invent a fake company) — not a real Outlook/Gmail clone — or hosts and Google
> Safe Browsing may flag and kill the URL mid-week. Take the deployment down after.

---

## 0. One-time prep (local)

The repo isn't a git repo yet and hosts deploy from git. From the `phishsim` folder:

```bash
git init
git add .
git commit -m "PhishSim deploy"
```

`.dockerignore` already excludes `.venv/`, `_mailhog/`, `instance/`, and `.env`, so
none of your local junk or secrets ship in the image. **Do not commit a real `.env`.**

Create a GitHub repo and push:

```bash
git branch -M main
git remote add origin https://github.com/<you>/phishsim.git
git push -u origin main
```

---

## 1. Get a real SMTP sender

**Option A — Gmail app password (fastest for a small list):**
1. Enable 2-Step Verification on the Google account.
2. Google Account → Security → **App passwords** → generate one for "Mail".
3. Use `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_USE_TLS=true`,
   `SMTP_USER=you@gmail.com`, `SMTP_PASSWORD=<16-char app password>`.

**Option B — SendGrid (more "proper", 100 emails/day free):**
1. Create an API key with Mail Send permission; verify a Single Sender.
2. `SMTP_HOST=smtp.sendgrid.net`, `SMTP_PORT=587`, `SMTP_USER=apikey`,
   `SMTP_PASSWORD=<the API key>`, `SMTP_USE_TLS=true`.

Tell recipients to check **spam** — simulated phishing often lands there.

---

## 2. Deploy (Render — UI path, matches render.yaml)

A persistent disk needs the **Starter** instance (~$7/mo); the free tier has no disk
and sleeps, which loses your campaign data on restart. For a graded week, Starter is
worth it. (Cheaper/free alternatives: **Fly.io** and **Railway** — see §5.)

1. Render → **New** → **Blueprint** → connect your GitHub repo. It reads `render.yaml`.
2. Click deploy. Render builds the Dockerfile, mounts the 1 GB disk at `/app/instance`,
   and auto-generates `SECRET_KEY`.
3. When prompted for the `sync:false` vars, set:
   - `ADMIN_EMAIL` = your email
   - `ADMIN_PASSWORD` = the strong one you generated
   - `SMTP_USER`, `SMTP_PASSWORD` = from §1
   - `BASE_URL` = leave blank for now
4. First deploy finishes → copy your URL, e.g. `https://phishsim-xxxx.onrender.com`.
5. Set **`BASE_URL`** to that exact URL → **Manual Deploy / Save** (redeploys).
   Tracking links won't work until this matches your public URL.

---

## 3. Smoke test (do this before the presentation)

```bash
# health
curl https://<your-url>/health          # -> {"database":"ok","status":"ok"}
```

Then in a browser:
1. `https://<your-url>` → log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.
2. Create a campaign → **landing page = Custom** (fake company name).
3. Add **only yourself** as the first target → **Send now** → confirm the email
   arrives (check spam) → click the link → fake login → submit → training page.
4. Confirm the funnel + Reported counts update in the dashboard.
5. Only after that works, import the rest of your **consented** list.

---

## 4. During / after

- Keep the Render service running the whole week (Starter doesn't sleep).
- Scheduler runs in-process (file-locked), so scheduled/drip sends work with no extra service.
- **Teardown:** Render → the service → **Settings → Delete**, and delete the disk.
  Revoke the Gmail app password / SendGrid key. Delete the GitHub repo if you like.

---

## 5. Alternatives to Render

**Fly.io** (has a free allowance):
```bash
fly launch --no-deploy            # detects the Dockerfile
fly volumes create phishsim_data --size 1   # mount at /app/instance in fly.toml
fly secrets set FLASK_ENV=production SECRET_KEY=... ADMIN_EMAIL=... \
  ADMIN_PASSWORD=... SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_USE_TLS=true \
  SMTP_USER=... SMTP_PASSWORD=... DATABASE_URL=sqlite:////app/instance/phishsim.db
fly deploy
fly secrets set BASE_URL=https://<app>.fly.dev   # after you know the URL
```

**Railway**: New Project → Deploy from repo → add a Volume mounted at `/app/instance`
→ set the same env vars in Variables → it builds the Dockerfile automatically.

All three give HTTPS automatically. The env vars are identical everywhere — only the
disk/volume and secret-setting UI differ.
