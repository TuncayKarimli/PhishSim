# PhishSim — Week-Long Demo Deployment Runbook

Goal: a persistent, HTTPS, publicly reachable instance for ~1 week with two live presentations, sending **real** simulated emails to a **small, consented** list.

> **Scope guardrail.** This is a security-awareness *demo*. Only send to people who said yes (classmates + your teacher). Use the **Custom / company-branded** landing page (invent a fake company) — not a real Outlook/Gmail clone — or hosts and Google Safe Browsing may flag and kill the URL mid-week. Take the deployment down after.

---

## 0. One-time prep (local)

### Clone the repository

If you haven't downloaded the project yet, clone it from GitHub:

```bash
git clone https://github.com/TuncayKarimli/PhishSim.git
cd PhishSim
```

The cloned project is already a Git repository, so you do not need to run `git init`.

### Prepare your deployment repository

If you want to deploy your own copy, fork the project on GitHub and clone your fork instead:

```bash
git clone https://github.com/<your-username>/PhishSim.git
cd PhishSim
```

Replace `<your-username>` with your GitHub username.

Your fork is already connected to your GitHub account through the `origin` remote. You do not need to run `git remote add origin` or initialize the repository again.

After making any necessary changes, you can push them to your fork:

```bash
git status
git add .
git commit -m "Prepare PhishSim deployment"
git push origin main
```

Only create a commit if you have actually made changes. For contributions to the original project, use a separate branch and submit a Pull Request.

### Protect sensitive files

Before committing or pushing changes, make sure you do not include sensitive files such as `.env`, API keys, passwords, or other credentials.

The repository's `.dockerignore` excludes local files such as `.venv/`, `_mailhog/`, `instance/`, and `.env` from the Docker build context.

**Important:** `.dockerignore` and `.gitignore` serve different purposes:

- `.dockerignore` excludes files from the Docker build context.
- `.gitignore` prevents specified untracked files from being added to Git by default.

A file excluded by `.dockerignore` can still be committed to Git.

Review `.gitignore` and use `git status` before committing any changes. Never commit a real `.env` file containing credentials.

---

## 1. Get a real SMTP sender

**Option A — Gmail app password (fastest for a small list):**

1. Enable 2-Step Verification on the Google account.
2. Google Account → Security → **App passwords** → generate one for "Mail".
3. Use `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_USE_TLS=true`, `SMTP_USER=you@gmail.com`, `SMTP_PASSWORD=<16-char app password>`.

**Option B — SendGrid:**

1. Create an API key with Mail Send permission; verify a Single Sender.
2. `SMTP_HOST=smtp.sendgrid.net`, `SMTP_PORT=587`, `SMTP_USER=apikey`, `SMTP_PASSWORD=<the API key>`, `SMTP_USE_TLS=true`.

Check the provider's current pricing, sending limits, and eligibility before deployment.

Tell recipients to check **spam** — simulated phishing often lands there.

---

## 2. Deploy (Render — UI path, matches render.yaml)

A persistent disk requires a paid Render instance; the free tier does not provide persistent disks and may sleep. Without persistent storage, campaign data can be lost when an instance restarts or is replaced.

Check Render's current pricing before selecting an instance. Alternatives include **Fly.io** and **Railway** — see §5.

1. Render → **New** → **Blueprint** → connect your GitHub repo. It reads `render.yaml`.
2. Click deploy. Render builds the Dockerfile, mounts the 1 GB disk at `/app/instance`, and auto-generates `SECRET_KEY`, as configured in the deployment blueprint.
3. When prompted for the `sync:false` vars, set:
   - `ADMIN_EMAIL` = your email
   - `ADMIN_PASSWORD` = the strong one you generated
   - `SMTP_USER`, `SMTP_PASSWORD` = from §1
   - `BASE_URL` = leave blank for now
4. First deploy finishes → copy your URL, e.g. `https://phishsim-xxxx.onrender.com`.
5. Set **`BASE_URL`** to that exact URL → save the environment change and redeploy if required. Tracking links won't work correctly until this matches your public URL.

---

## 3. Smoke test (do this before the presentation)

```bash
# Health check
curl https://<your-url>/health
# Expected response: {"database":"ok","status":"ok"}
```

Replace `<your-url>` with your deployed application's hostname.

Then in a browser:

1. `https://<your-url>` → log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.
2. Create a campaign → **landing page = Custom** (fake company name).
3. Add **only yourself** as the first target → **Send now** → confirm the email arrives (check spam) → click the link → enter dummy test credentials → submit → training page.
4. Confirm the funnel + Reported counts update in the dashboard.
5. Only after that works, import the rest of your **consented** list.

Never enter real account passwords during testing.

---

## 4. During / after

- Keep the Render service running the whole week (select an instance that does not sleep).
- Scheduler runs in-process (file-locked), so scheduled/drip sends work with no extra service.
- **Teardown:** Render → the service → **Settings → Delete**, and delete the disk. Revoke the Gmail app password / SendGrid key. Delete the GitHub repo if you like.
- Remove unnecessary campaign data after the demonstration and avoid retaining submitted test credentials.

---

## 5. Alternatives to Render

**Fly.io** (check current pricing and available allowances):

```bash
fly launch --no-deploy

# Create a persistent volume
fly volumes create phishsim_data --size 1

# Configure the volume mount at /app/instance in fly.toml
# before deploying.

fly secrets set FLASK_ENV=production SECRET_KEY=... ADMIN_EMAIL=... \
  ADMIN_PASSWORD=... SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_USE_TLS=true \
  SMTP_USER=... SMTP_PASSWORD=... DATABASE_URL=sqlite:////app/instance/phishsim.db

fly deploy

# Set BASE_URL after you know the public URL
fly secrets set BASE_URL=https://<app>.fly.dev
```

**Railway:** New Project → Deploy from repo → add a Volume mounted at `/app/instance` → set the same env vars in Variables → it builds the Dockerfile automatically.

All three platforms support HTTPS. The environment-variable configuration is similar, but disk/volume management and secret-setting interfaces differ. Check each provider's current documentation and pricing before deployment.
