# X GYM Mahipalpur — Management System

Flask + SQLite backend, a password-protected **admin panel**, and the public gym
website. Admin v2 turns the old member list into a complete front-desk tool:
memberships with valid-till dates, renew/extend, payment & dues tracking, and a
separate Revenue page.

---

## ✨ Admin v2 — what's new

The admin is now five separate pages (sidebar on laptop, bottom tab bar on phone):

| Page | What it's for |
|---|---|
| **Home** | Today at a glance (members only — **no money figures here**), who's expiring / just expired with one-tap *Renew* and WhatsApp, quick actions, and doors to the other pages |
| **Members** | Search, filter (Active / Expiring soon / Expired / Dues pending, men / women), sort, export CSV. Tap a member to open their profile |
| **Revenue** | A page of its own: everything received, split **by source** (membership fees · trainer/PT fees · items sold · other) and **by payment method** (cash · UPI · card · bank), with a chart, comparison with the previous period, pending dues and a full ledger |
| **Messages** | Expiry reminders, broadcasts, and a **History** tab so failed WhatsApp sends are finally visible |
| **Settings** | Edit plan prices, download a database backup, security info |

### Members: membership, valid-till and payments
- **Add member** is one form with three clear steps: ① details → ② **membership**
  (plan chips with live prices, start date, and a big *"Valid till 20 Nov 2026 · 31 days"*
  banner) → ③ **payment** (price, paid now, balance, how paid). A part-payment is fine —
  the rest becomes *dues*.
- **Renew / extend** (the big red button on every expired/expiring member and in every
  profile) — separate from Edit. If the member is still active the new period starts the
  **day after** their current expiry, so no days are lost; if expired it starts today.
  Choose 1/3/6/12 months or **Custom** (any valid-till date — also handy for free "bonus days"
  with price ₹0). Edit is now only for fixing mistakes.
- **Member profile** shows: valid-till with a countdown bar, total paid, membership billed,
  **dues**, full membership history (every renewal), and every payment. From there you can
  *Collect dues*, *Record payment*, fix a price/payment, or **Undo a renewal** done by mistake.
- After adding/renewing, a success sheet offers a **WhatsApp receipt** in one tap.
- Pre-existing members are migrated automatically and show *"No payment on record"* —
  they never get fake dues.

### Revenue page
- Periods: Today · This week · This month · Last month · Last 30 days · **This FY (Apr–Mar)** · Custom.
- Compares with the same stretch of the previous period (e.g. "141% vs the same days last month").
- **Record income** for things that aren't memberships: trainer fees, supplements/drinks
  sold, day passes, locker rent… to a member or a walk-in.
- Ledger with search + filters, edit/delete a wrong entry, **Export CSV** (opens cleanly in Excel).
- Deleting a member **never** deletes the money they paid — it stays in revenue.
- **Optional PIN lock**: set `REVENUE_PIN` and the Revenue page (and edits to payments)
  need the PIN, so staff can use Members while only you see the numbers.

### Also fixed / improved
- Admin works properly on phones (the old one had stretched avatars and giant stacked buttons).
- Valid-till uses month-end-safe maths (31 Jan + 1 month = 28 Feb) — the old browser maths overflowed into March.
- A wrong login is rate-limited; passwords compared in constant time.
- Wrong admin data can't half-save: every add/renew runs as one database transaction.
- WhatsApp reminders skip already-expired members (the approved template says *"expiring…"*).
- `DB_PATH` lets you point the database at a persistent disk.
- **Restore from backup** in Settings (previews what's inside, keeps a safety copy first).

---

## 🧭 Daily use — cheat sheet

| I want to… | Do this |
|---|---|
| Sign up someone new | Members → **Add member** → fill the 3 steps → *Save* → (optional) *Send WhatsApp receipt* |
| Renew someone | Home → **Renew / extend a member**, or the **Renew** button on their row |
| Someone paid only part | In the form set *Paid now* lower — the balance is saved as dues |
| Collect the remaining money | Member → profile → **Collect dues** (or Revenue → *Pending dues* → Collect) |
| Sell a protein shake / PT package | Home → **Record a payment or sale** (or Revenue → *Record income*) |
| See how much came in | **Revenue** → choose the period |
| Renewed the wrong person | Profile → membership history → **Undo renewal** |
| Change the prices | Settings → Plan prices |
| Keep my data safe | Settings → **Download full backup** (do this weekly) |

---

## >>> Fill these in yourself before deploying <<<

Copy `.env.example` to `.env` in this folder, then fill in:

| Variable | What it's for |
|---|---|
| `ADMIN_PASSWORD` | Your admin login password |
| `SECRET_KEY` | Random string that signs the login cookie — `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `REVENUE_PIN` | *(optional)* a PIN that guards the Revenue page. Leave empty for no extra lock |
| `DB_PATH` | *(optional)* where the database lives, e.g. `/var/data/xgym.db` on a persistent disk |
| `SESSION_COOKIE_SECURE` | Set to `1` once the site runs on https |
| `META_ACCESS_TOKEN`, `META_PHONE_NUMBER_ID` | From Meta for Developers → WhatsApp → API Setup |
| `META_TEMPLATE_NAME` | An **approved** template name, exactly |
| `CRON_SECRET` | Secret for the daily reminder trigger (`X-CRON-SECRET` header) |

Without the Meta values everything still works — only the *automatic* WhatsApp sending is
off (the green WhatsApp buttons that open WhatsApp with a ready message always work).

---

## Running locally

```bash
pip install -r requirements.txt
cp .env.example .env     # then edit .env
python3 app.py
```
Public site: `http://127.0.0.1:5000/` · Admin: `http://127.0.0.1:5000/admin`

### Tests
```bash
python3 -m unittest discover -s tests -v
```
62 backend tests (money rules, renewals, dues, revenue totals, PIN lock, migration, backup/restore…).
They use a temporary database — your real `xgym.db` is never touched.

---

## Deploying

**See `DEPLOY.md`** for the full step-by-step guide (Render blueprint included: `render.yaml`).
In short: push to GitHub (without `.env`), create the service, paste the environment variables,
and make sure your data is safe — a persistent disk (`DB_PATH`) or regular **Settings → Download
backup**; **Settings → Restore from a backup** puts it back after a reset.

### Daily auto-reminders
`POST /api/reminders/check-tomorrow` with header `X-CRON-SECRET: <CRON_SECRET>` reminds everyone
expiring exactly tomorrow. Point cron-job.org / GitHub Actions / Render Cron at it once a day.

---

## How money is stored (for the curious / for interviews)

```
members      id, name, phone, gender, plan, start (= joined), expiry (= valid till)
memberships  one row per period (first join + every renewal): plan, start, expiry, price
payments     one row per payment: category, amount, method, paid_on, member?, membership?
plan_prices  (gender, months) → price
```
`Dues = Σ membership prices − Σ membership payments`. Revenue = Σ payments in a date range.
`members.plan/expiry` always mirror the latest membership so reminders and filters keep working.
Valid-till is **inclusive**: a 1-month plan starting 14 Oct is valid through 13 Nov.

---

## Files in this folder

```
DEPLOY.md               — Step-by-step deployment guide
render.yaml / Procfile  — Hosting config (Render blueprint, gunicorn start command)
.env                    — Ready-to-run secrets (git-ignored — never upload it)
app.py                  — Flask backend (members, memberships, payments, revenue, WhatsApp)
xgym-admin.html         — Admin panel v2 (single file, no build step)
xgym-websiteee.html     — Public gym website (unchanged)
tests/test_api.py       — Backend test suite
requirements.txt        — Python dependencies (unchanged)
.env.example            — Copy to .env and fill in
backup-v1/              — The previous admin + backend, in case you want to compare
Procfile, .gitignore, images/
```

---
## Earlier pass — bug fixes & deployment prep

**Bugs fixed:**
- Reminder/broadcast sending was calling a function that didn't exist
  (`send_whatsapp_template`) — every "Send Reminder" or scheduled cron
  reminder was silently crashing. Now routes through the real function.
- Member list mislabeled every plan except 3-month as "1 Month" — fixed
  with a proper plan → label map.
- Broken HTML nesting in the Add/Edit Member modal (Plan dropdown was
  nested inside the Expiry Date field's container).
- Stale "Check Twilio setup" error message from before the switch to
  Meta's WhatsApp Cloud API — updated.
- Removed a chunk of dead, unreachable code left over from an earlier
  version of the WhatsApp-sending function.
- **Security:** the admin password used to be hardcoded in plain text
  inside `xgym-admin.html`, visible to anyone via "View Page Source",
  and login was checked entirely in the browser (bypassable via
  DevTools). This is now a real server-side session login — the
  password lives only in `.env`, and every data API route is protected
  by a login check.

**Your ask — video optional in broadcasts:**
The "Broadcast Message" modal's video URL field is now clearly labeled
optional; leaving it blank sends a text-only broadcast. One thing worth
knowing: if a template was approved in Meta's Template Builder *with a
mandatory video header*, Meta's API itself will still reject a send with
no video attached — that's enforced on Meta's side, not something any
app code can override. If you want broadcasts that reliably work with
or without video, approve a second, text-only template in Meta and pick
between the two from the Template dropdown (the dropdown already
supports multiple templates).

**Small additions:**
- **Export CSV** button on the dashboard — downloads the current member
  list (name, phone, gender, plan, dates, status).
- **Esc key** closes whichever modal is open.
- **`/api/health`** endpoint — most hosting platforms (Render, Railway,
  Fly.io) want a lightweight health-check URL; this is it.

The public website (`xgym-websiteee.html`) was left untouched — I didn't
find bugs in it, and you asked to keep the original frontend files
intact.

---

## Earlier pass — site completion

- **Admin → Main Site button:** after logging in to `/admin`, the top bar has a
  "🌐 Main Site" button. The public site deliberately has **no** link back to the admin.
- **Photos:** the gym's real photos are in `images/` (upscaled + cleaned). The gallery
  now shows only zones that have a real photo (Weight Zone, Training Floor, Cardio Area,
  Strength Area, Signboard). See `images/README.txt` for file names and how to swap one.
- **Transformations:** the before/after pair is replaced by a single
  "Owner's Own Transformation" feature (`images/owner-transformation.jpg`).
  Edit the wording in `xgym-websiteee.html` (search for `owner-copy`).
- **Gallery:** photos open in a full-screen viewer on click; fixed a mobile
  layout bug where tiles collapsed to zero height on phones.
- **Backend fixes:** dates now use Indian time (cloud servers run UTC, which made
  expiry counts and the daily reminder wrong between midnight and 5:30 AM);
  editing a member to an already-used phone number now shows a clear message
  instead of a server error; add/edit requests are validated server-side.
- **Location section:** fixed broken HTML around the working-hours text.
