# BudTut — demo app (frontend + backend)

Everything you need to test **registration, login and job posting**.

## Run it

```bash
cd budtut-app
npm install
npm start
```

Open **http://localhost:3000** (the backend serves the website too — use this address, not the .html file).
Requires Node.js 18+.

## What works

| Feature | How |
|---|---|
| Registration (Private person / Sole trader / Company) | Header → Zaloguj się → Utwórz konto. JDG/company use a **demo** registry lookup: NIP `123-456-32-18` or KRS `0000123456`. |
| Login / logout | Header dropdown. Session token is stored in the browser (localStorage). |
| Post a job | Header → **Dodaj zlecenie** (login required). The job appears at the top of **Przeglądaj → Zlecenia** with a green "Twoje zlecenie" tag. |
| Data | Saved in `data/db.json` (created on first run). Delete the file to reset everything. |

Sample jobs and contractors you see on the pages are still built into the frontend; only jobs you post go through the backend.

## API

| Method | Path | Notes |
|---|---|---|
| POST | `/api/auth/register` | `{type, first, last, email, phone, password, terms, position?, authority?, business?:{number, confirmed}}` → `{token, user}` |
| POST | `/api/auth/login` | `{email, password}` → `{token, user}` |
| GET | `/api/auth/me` | Bearer token |
| POST | `/api/auth/logout` | Bearer token |
| GET | `/api/lookup?type=jdg\|company&number=` | Demo company registry |
| GET | `/api/jobs` | All posted jobs, newest first |
| GET | `/api/jobs/mine` | Your jobs (Bearer) |
| GET | `/api/jobs/:id` | One job |
| POST | `/api/jobs` | `{title, description, category, city, district?, budget|null}` (Bearer) |
| GET | `/api/jobs/:id/contact` | Poster's name/e-mail/phone (Bearer, rate-limited) |
| PATCH | `/api/jobs/:id/status` | `{status: 'open'\|'done'}` — own jobs only. Jobs are never deleted, only marked done, so job history is preserved for future stats. |

Auth header: `Authorization: Bearer <token>`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port the server listens on. Most hosts (Render included) set this for you. |
| `DATA_DIR` | `./data` | Where `db.json` lives. **Must** point at a persistent disk on any host with an ephemeral filesystem — otherwise every deploy/restart wipes all users, jobs and reviews. |
| `CANONICAL_HOST` | *(unset)* | e.g. `budtut.eu`. When set, any other host (like `www.budtut.eu`) or plain HTTP is 301-redirected here. Leave unset for local dev. |
| `NODE_ENV` | *(unset)* | Set to `production` on the live server (used by the HTTPS redirect check). |
| `ADMIN_TOKEN` | *(unset)* | Enables the `/api/admin/*` endpoints (deletion-request review — see `admin.js`). Must be 16+ chars. Leave unset in dev; the routes 404 without it. |

## Deploying to Render (budtut.eu)

This repo includes `render.yaml`, so Render can create the service from one click:

1. Push this folder to a **GitHub** repo (see commands below).
2. On [render.com](https://render.com), **New → Blueprint**, pick that repo, and click **Apply**.
   This creates the web service on the **Starter** plan with a 1 GB persistent disk mounted at
   `/data` and `DATA_DIR`/`NODE_ENV`/`CANONICAL_HOST`/`ADMIN_TOKEN` already set — free plans can't
   attach a disk and also sleep when idle, which would corrupt the JSON database, so Blueprint
   deliberately picks Starter.
3. Once it deploys, open the service → **Settings → Custom Domains** → add `budtut.eu` and
   `www.budtut.eu`. Render shows the exact DNS records to create (an `A`/`ANAME` for the apex and
   a `CNAME` for `www`) — add those at whatever registrar/DNS you bought the domain through. TLS
   certificates are issued automatically once DNS points at Render.
4. Set up mail for the addresses the legal pages already reference — `kontakt@`, `privacy@`,
   `dsa@`, `pomoc@`, `kariera@budtut.eu` (see `BT.COMPANY` in `budtut/pages-core.js`) — with your
   registrar's free forwarding or a provider like Cloudflare Email Routing / Zoho Mail, otherwise
   those addresses will bounce.

```bash
git init
git add .
git commit -m "BudTut launch"
git branch -M main
git remote add origin https://github.com/<you>/budtut.git
git push -u origin main
```

Update the `budtut` service (rebuild the frontend into `public/index.html`, commit, push) any time
`budtut/*.js`, `budtut/*.html` or `budtut/styles.css` change — Render auto-deploys on every push
to `main`.

## Before going to production

- Fill in `BT.COMPANY` in `budtut/pages-core.js` with the real legal entity data (name, KRS/NIP/REGON,
  registry court, share capital, representative, mediators, effective date) — the bracketed
  placeholders are highlighted on the live legal pages until replaced, and a lawyer should review
  Terms/Privacy/Cookies before they govern real users.
- Wire up real payment collection for the 5 zł verification fee (Przelewy24 is the common choice
  for PLN card/BLIK payments in Poland) — right now a verification request is only recorded, not paid.
- Replace the JSON file with a real database (PostgreSQL) once traffic/data size warrants it — `db`
  in `server.js` is the only storage layer, and `DATA_DIR` must sit on a persistent disk regardless.
- Replace `lookupCompany()` with real CEIDG (JDG) and KRS / GUS / Biała Lista VAT calls (server side only).
- Add e-mail confirmation and password reset, and move the rate limiter to Redis if you run more
  than one server instance (the current one is in-memory per-process).
- Company verification (identity + representation) is only a screen for now; the endpoints for it are not built yet.
- `data/db.json` has no automated backup — on Render, periodically download it (or snapshot the
  disk) until a real database is in place.
