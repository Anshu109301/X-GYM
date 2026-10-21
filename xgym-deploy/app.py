"""
X GYM Mahipalpur — Flask backend (v2)

What this file does
  • Serves the public website (/) and the admin panel (/admin)
  • Members + membership periods (join / renew / extend) with payment tracking
  • Revenue tracking by source (membership, trainer fees, items sold, other)
    and by payment method (cash, UPI, card, bank)
  • WhatsApp reminders / broadcasts through the Meta Cloud API
  • A password-protected admin API (server-side session login)

Money rules (read this once, it explains the whole data model)
  members      one row per person. `start` = the day they JOINED, `expiry` = the
               day their current membership is valid TILL (inclusive).
  memberships  one row per membership period (the first join, then every renewal).
               `price` = what that period costs after any discount.
  payments     one row per payment actually received, for ANY reason (membership,
               personal training, items sold, other). Revenue = sum of payments.
  Dues         = sum(period prices) − sum(membership payments), per member.
"""

from flask import Flask, jsonify, request, send_from_directory, send_file, session
from werkzeug.exceptions import HTTPException
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from contextlib import contextmanager
import calendar
import hmac
import os
import re
import sqlite3
import tempfile
import time
import uuid

# python-dotenv loads variables from a .env file into os.environ
from dotenv import load_dotenv
load_dotenv()

import requests

app = Flask(__name__, static_folder=None)

# The gym is in Delhi, but cloud hosts (Render/Railway) run on UTC. Between
# midnight and 5:30 AM IST, "today" on a UTC server is still *yesterday* — which
# made expiry counts and the daily reminder run off by one day. IST has no DST,
# so a fixed +5:30 offset is exact.
IST = timezone(timedelta(hours=5, minutes=30))


def today_ist():
    return datetime.now(IST).date()


def now_ist_str():
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGES_DIR = os.path.join(BASE_DIR, "images")

# DB_PATH can be pointed at a persistent disk (e.g. Render: /var/data/xgym.db) so
# the database survives redeploys. Default: xgym.db next to this file.
DB_PATH = os.environ.get("DB_PATH") or os.path.join(BASE_DIR, "xgym.db")
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

# ── Meta WhatsApp Cloud API config (from .env — never hardcode these) ──
META_ACCESS_TOKEN = os.environ.get("META_ACCESS_TOKEN")
META_PHONE_NUMBER_ID = os.environ.get("META_PHONE_NUMBER_ID")
META_TEMPLATE_NAME = os.environ.get("META_TEMPLATE_NAME", "gym_membership_reminder")
CRON_SECRET = os.environ.get("CRON_SECRET", "change-me")

# ── Admin panel login (server-side session) ──
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "11223344")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me-in-.env")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024        # largest accepted upload (a database backup)
# On a real https host set SESSION_COOKIE_SECURE=1 in the environment.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"

# Optional second lock: if REVENUE_PIN is set, the Revenue page (and anything that
# lists gym-wide money) asks for this PIN on top of the admin login. Handy when
# front-desk staff use the admin but only the owner should see the numbers.
REVENUE_PIN = os.environ.get("REVENUE_PIN", "").strip()

if app.secret_key == "dev-secret-change-me-in-.env" or ADMIN_PASSWORD == "11223344":
    print("⚠️  Using default ADMIN_PASSWORD/SECRET_KEY — set both in .env before going live.")

if not META_ACCESS_TOKEN or not META_PHONE_NUMBER_ID:
    print("⚠️  Meta WhatsApp credentials not set — reminder sending will fail until .env is configured.")


# ────────────────────────────────
# ERRORS — every /api/* failure comes back as JSON {"error": "..."} so the admin
# panel can show a readable message instead of choking on an HTML error page.
# ────────────────────────────────

class ApiError(Exception):
    def __init__(self, message, status=400, code=None, **extra):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.extra = extra


@app.errorhandler(ApiError)
def handle_api_error(e):
    body = {"error": e.message}
    if e.code:
        body["code"] = e.code
    body.update(e.extra)
    return jsonify(body), e.status


@app.errorhandler(Exception)
def handle_unexpected(e):
    if isinstance(e, HTTPException):
        if request.path.startswith("/api/"):
            return jsonify({"error": e.description or e.name}), e.code
        return e
    app.logger.exception("Unhandled error")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Unexpected server error. Check the server log."}), 500
    return "Server error", 500


@app.after_request
def security_headers(resp):
    """Basic hardening for every response."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"          # member + money data must never sit in a browser/proxy cache
    if request.path == "/admin":
        resp.headers["X-Frame-Options"] = "DENY"            # the admin panel can't be embedded in another site
    return resp


# ────────────────────────────────
# AUTH
# ────────────────────────────────

# Tiny in-memory brute-force guard: 8 wrong attempts in 15 minutes locks that
# client out for the rest of the window. (Per-process; fine for a single gym.)
_FAILS = {}
FAIL_LIMIT = 8
FAIL_WINDOW = 15 * 60


def _client_key(kind):
    fwd = request.headers.get("X-Forwarded-For", "")
    ip = fwd.split(",")[0].strip() if fwd else (request.remote_addr or "?")
    return f"{kind}:{ip}"


def is_throttled(kind):
    key, now = _client_key(kind), time.time()
    recent = [t for t in _FAILS.get(key, []) if now - t < FAIL_WINDOW]
    _FAILS[key] = recent
    return len(recent) >= FAIL_LIMIT


def record_failure(kind):
    _FAILS.setdefault(_client_key(kind), []).append(time.time())


def clear_failures(kind):
    _FAILS.pop(_client_key(kind), None)


def secure_equals(a, b):
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def login_required(f):
    """Protects an API route behind the admin session cookie set by /api/login."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return jsonify({"error": "Not logged in."}), 401
        return f(*args, **kwargs)
    return wrapper


def revenue_unlocked():
    return (not REVENUE_PIN) or bool(session.get("revenue_unlocked"))


def revenue_required(f):
    """Extra lock for gym-wide money data (only active when REVENUE_PIN is set)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not revenue_unlocked():
            return jsonify({"error": "Revenue is locked. Enter the revenue PIN.", "code": "revenue_locked"}), 403
        return f(*args, **kwargs)
    return wrapper


# ────────────────────────────────
# CONSTANTS
# ────────────────────────────────

# Where the money comes from (what the revenue page splits by).
CATEGORIES = {
    "membership": "Membership fees",
    "personal_training": "Trainer / PT fees",
    "products": "Items sold",
    "other": "Other income",
}

# How the money arrived ("platform" in the owner's words).
METHODS = {
    "cash": "Cash",
    "upi": "UPI",
    "card": "Card",
    "bank": "Bank transfer",
    "other": "Other",
}

VALID_PLANS = {"0", "1", "3", "6", "12"}          # "0" = custom length
SOON_DAYS = 5                                      # "expiring soon" = within 5 days
MAX_AMOUNT = 1_000_000                             # ₹10 lakh per entry — catches typos

# Seeded from the public website's price cards; editable later in Admin → Settings.
DEFAULT_PLAN_PRICES = {
    "male":   {"1": 1000, "3": 2500, "6": 4500, "12": 8500},
    "female": {"1": 600,  "3": 1500, "6": 2700, "12": 3600},
}

# ── Template registry ──
# Every entry here must correspond to an ALREADY-APPROVED Meta template.
# "variables" lists what {{2}}, {{3}}... mean (name-filling {{1}} is automatic per-recipient).
# Set "has_media": True + "media_type": "video" (or "image") for templates with a media header.
AVAILABLE_TEMPLATES = {
    "gym_membership_reminder": {
        "label": "Membership Expiry Reminder",
        "extra_variables": ["urgency", "expiry_date"],   # fills {{2}}, {{3}} — auto-built by the reminder logic
        "has_media": False
    },
    "gym_announcement": {
        "label": "General Announcement / Promo",
        "extra_variables": ["message"],   # fills {{2}} — admin types this once per broadcast
        "has_media": True,
        "media_type": "video"
    }
    # Add more templates here after creating + approving them in Meta's Template Builder.
}


# ────────────────────────────────
# DATABASE
# ────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def read_conn():
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def tx():
    """A write transaction: everything inside commits together or not at all.
    (Renewing = new period + member update + payment — it must never half-save.)"""
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


REQUIRED_MEMBER_COLUMNS = {"id", "name", "phone", "gender", "plan", "start", "expiry"}


def get_existing_columns(conn, table_name):
    """Returns the set of column names currently in a table, or None if the table doesn't exist."""
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    if not rows:
        return None
    return {row["name"] for row in rows}


def init_db():
    conn = get_db()

    # ── Self-healing check: does a 'members' table already exist with the WRONG columns? ──
    # (An old schema — e.g. from an earlier dummy-data script — can sit in xgym.db.
    # CREATE TABLE IF NOT EXISTS silently does nothing in that case, which is what
    # used to cause "data not saving".)
    existing_cols = get_existing_columns(conn, "members")

    if existing_cols is not None and not REQUIRED_MEMBER_COLUMNS.issubset(existing_cols):
        backup_name = f"members_backup_{int(datetime.now().timestamp())}"
        print(f"⚠️  Found an existing 'members' table with incompatible columns: {existing_cols}")
        print(f"⚠️  Renaming it to '{backup_name}' so your old data isn't lost, and creating a fresh one.")
        conn.execute(f"ALTER TABLE members RENAME TO {backup_name}")
        conn.commit()
        existing_cols = None  # forces the CREATE TABLE below to run fresh

    if existing_cols is None:
        conn.execute("""
            CREATE TABLE members (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE,
                gender TEXT CHECK(gender IN ('male','female')) NOT NULL,
                plan TEXT NOT NULL,
                start DATE NOT NULL,
                expiry DATE NOT NULL
            )
        """)
        print("✅ Created fresh 'members' table with the correct schema.")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT NOT NULL,
            sent_date DATE NOT NULL,
            days_left INTEGER,
            status TEXT CHECK(status IN ('sent','failed')) DEFAULT 'sent',
            error TEXT,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS broadcast_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT NOT NULL,
            template_name TEXT NOT NULL,
            sent_date DATE NOT NULL,
            status TEXT CHECK(status IN ('sent','failed')) DEFAULT 'sent',
            error TEXT,
            FOREIGN KEY (member_id) REFERENCES members(id)
        )
    """)

    # ── v2 tables (additive — the members table above is never altered) ──
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memberships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT NOT NULL,
            plan TEXT NOT NULL,
            start DATE NOT NULL,
            expiry DATE NOT NULL,
            price INTEGER NOT NULL DEFAULT 0 CHECK(price >= 0),
            note TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id TEXT,
            payer_name TEXT,
            membership_id INTEGER,
            category TEXT NOT NULL,
            amount INTEGER NOT NULL CHECK(amount > 0),
            method TEXT NOT NULL,
            paid_on DATE NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS plan_prices (
            gender TEXT NOT NULL,
            months TEXT NOT NULL,
            price INTEGER NOT NULL CHECK(price >= 0),
            PRIMARY KEY (gender, months)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payments_paid_on ON payments(paid_on)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payments_member ON payments(member_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payments_membership ON payments(membership_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memberships_member ON memberships(member_id)")

    # Seed default plan prices once (never overwrites prices the owner has edited).
    if conn.execute("SELECT COUNT(*) FROM plan_prices").fetchone()[0] == 0:
        for gender, plans in DEFAULT_PLAN_PRICES.items():
            for months, price in plans.items():
                conn.execute("INSERT INTO plan_prices (gender, months, price) VALUES (?,?,?)", (gender, months, price))

    # Members that existed BEFORE v2 have no membership period yet. Give each one a
    # period built from their current plan/dates, with price 0 = "no payment recorded"
    # — so old members don't suddenly show fake dues.
    conn.execute("""
        INSERT INTO memberships (member_id, plan, start, expiry, price, note, created_at)
        SELECT m.id, m.plan, m.start, m.expiry, 0, 'Existing member — no payment recorded', m.start || ' 00:00:00'
        FROM members m
        WHERE NOT EXISTS (SELECT 1 FROM memberships s WHERE s.member_id = m.id)
    """)
    conn.commit()
    conn.close()


init_db()


# ────────────────────────────────
# HELPERS — dates, money, text
# ────────────────────────────────

def days_until(date_str):
    target = date.fromisoformat(date_str)
    return (target - today_ist()).days


def tenure_months(start_date_str):
    """How many months since this member's JOIN date — used for the 'how old is the member' filter."""
    start = date.fromisoformat(start_date_str)
    today = today_ist()
    return (today.year - start.year) * 12 + (today.month - start.month)


def format_date_display(date_str):
    return datetime.fromisoformat(date_str).strftime("%d %b %Y")


def add_months(d, n):
    """d + n calendar months. If the target month is shorter, clamps to its last day
    (31 Jan + 1 month = 28 Feb) — plain month arithmetic would overflow into March."""
    index = d.month - 1 + n
    year, month = d.year + index // 12, index % 12 + 1
    return date(year, month, min(d.day, calendar.monthrange(year, month)[1]))


def plan_end(start, months):
    """Last valid day of a membership that starts on `start` and runs `months` months.
    Inclusive: a 1-month plan starting 14 Oct is valid through 13 Nov."""
    return add_months(start, months) - timedelta(days=1)


def status_for(days_left):
    if days_left < 0:
        return "expired"
    if days_left <= SOON_DAYS:
        return "soon"
    return "active"


def plan_label(plan, start_str=None, expiry_str=None):
    plan = str(plan)
    if plan in ("1", "3", "6", "12"):
        return "1 Month" if plan == "1" else f"{plan} Months"
    if start_str and expiry_str:
        try:
            days = (date.fromisoformat(expiry_str) - date.fromisoformat(start_str)).days + 1
            return f"Custom · {days} day{'' if days == 1 else 's'}"
        except ValueError:
            pass
    return "Custom"


def parse_date(value, label="Date"):
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise ApiError(f"{label} must be a valid date.")


def parse_amount(value, label="Amount", default=None, allow_zero=True):
    """Whole rupees only. Accepts 1500, "1500", "1,500", "₹1500", 1500.0."""
    if value is None or (isinstance(value, str) and not value.strip()):
        if default is not None:
            return default
        raise ApiError(f"{label} is required.")
    if isinstance(value, bool):
        raise ApiError(f"{label} must be a number.")
    try:
        if isinstance(value, str):
            value = value.replace(",", "").replace("₹", "").strip()
        num = float(value)
    except (TypeError, ValueError):
        raise ApiError(f"{label} must be a number.")
    if num != num or num in (float("inf"), float("-inf")):
        raise ApiError(f"{label} must be a number.")
    if abs(num - round(num)) > 1e-9:
        raise ApiError(f"{label} must be a whole number of rupees.")
    num = int(round(num))
    if num < 0:
        raise ApiError(f"{label} can't be negative.")
    if num == 0 and not allow_zero:
        raise ApiError(f"{label} must be more than ₹0.")
    if num > MAX_AMOUNT:
        raise ApiError(f"{label} looks too large (max ₹10,00,000 per entry).")
    return num


def clean_text(value, max_len, label="Text"):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) > max_len:
        raise ApiError(f"{label} is too long (max {max_len} characters).")
    return text


def clean_choice(value, allowed, label):
    value = str(value or "").strip().lower()
    if value not in allowed:
        raise ApiError(f"Choose a valid {label}.")
    return value


def payment_date(value):
    """Defaults to today (IST). Future-dated payments are rejected — almost always a typo."""
    if value in (None, ""):
        return today_ist()
    d = parse_date(value, "Payment date")
    if d > today_ist():
        raise ApiError("Payment date can't be in the future.")
    return d


def get_json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Invalid or missing JSON data.")
    return data


# ────────────────────────────────
# PAGES + SESSION
# ────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    if is_throttled("login"):
        return jsonify({"error": "Too many attempts. Please wait a few minutes and try again."}), 429
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    if password and secure_equals(password, ADMIN_PASSWORD):
        clear_failures("login")
        session.permanent = True
        session["admin_authenticated"] = True
        return jsonify({"ok": True})
    record_failure("login")
    return jsonify({"error": "Incorrect password."}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("admin_authenticated", None)
    session.pop("revenue_unlocked", None)
    return jsonify({"ok": True})


@app.route("/api/session", methods=["GET"])
def check_session():
    return jsonify({"authenticated": bool(session.get("admin_authenticated"))})


@app.route("/api/debug/status", methods=["GET"])
@login_required
def debug_status():
    """
    Visit /api/debug/status in your browser any time to see exactly what's in
    the database — useful for confirming saves are actually happening.
    """
    with read_conn() as conn:
        members_cols = get_existing_columns(conn, "members")
        counts = {}
        for table in ("members", "memberships", "payments", "plan_prices", "reminders", "broadcast_log"):
            counts[table] = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
        sample = [dict(r) for r in conn.execute("SELECT * FROM members LIMIT 5").fetchall()]

    return jsonify({
        "db_path": DB_PATH,
        "db_file_exists": os.path.exists(DB_PATH),
        "members_table_columns": sorted(members_cols) if members_cols else None,
        "row_counts": counts,
        "sample_members": sample,
        "meta_configured": bool(META_ACCESS_TOKEN and META_PHONE_NUMBER_ID),
        "revenue_pin_enabled": bool(REVENUE_PIN),
    })


@app.route("/api/health")
def health_check():
    """Lightweight endpoint for deployment platforms (Render/Railway/etc.) to ping."""
    return jsonify({"status": "ok"})


@app.route("/")
def public_site():
    return send_from_directory(BASE_DIR, "xgym-websiteee.html")


@app.route("/images/<path:filename>")
def site_images(filename):
    """Serves the gym photos from the ./images folder (see images/README.txt)."""
    return send_from_directory(IMAGES_DIR, filename)


@app.route("/admin")
def admin_panel():
    resp = send_from_directory(BASE_DIR, "xgym-admin.html")
    resp.headers["Cache-Control"] = "no-store"     # always load the newest admin after an update
    return resp


# ────────────────────────────────
# MEMBERS — queries + serialisation
# ────────────────────────────────

# One query gives every member plus their money summary (no N+1 queries):
#   billed          = sum of all their membership period prices
#   paid_membership = membership payments received
#   paid_total      = everything they've paid (incl. trainer fees / items)
#   period_*        = the CURRENT (latest) membership period
MEMBER_SELECT = """
    SELECT m.*,
           cur.id    AS period_id,
           cur.start AS period_start,
           cur.price AS period_price,
           COALESCE((SELECT SUM(price)  FROM memberships WHERE member_id = m.id), 0)                          AS billed,
           COALESCE((SELECT SUM(amount) FROM payments WHERE member_id = m.id AND category = 'membership'), 0) AS paid_membership,
           COALESCE((SELECT SUM(amount) FROM payments WHERE member_id = m.id), 0)                             AS paid_total,
           (SELECT MAX(paid_on) FROM payments WHERE member_id = m.id)                                         AS last_paid_on
    FROM members m
    LEFT JOIN memberships cur
           ON cur.id = (SELECT id FROM memberships WHERE member_id = m.id ORDER BY expiry DESC, id DESC LIMIT 1)
"""


def member_dict(row):
    m = dict(row)
    d = days_until(m["expiry"])
    m["days_left"] = d
    m["status"] = status_for(d)
    m["tenure_months"] = tenure_months(m["start"])
    m["joined"] = m["start"]
    m["plan_label"] = plan_label(m["plan"], m.get("period_start") or m["start"], m["expiry"])
    m["due"] = max(0, m["billed"] - m["paid_membership"])
    return m


def fetch_members(conn, where="", params=()):
    rows = conn.execute(f"{MEMBER_SELECT} {where} ORDER BY m.name COLLATE NOCASE", params).fetchall()
    return [member_dict(r) for r in rows]


def get_member_row(member_id):
    with read_conn() as conn:
        row = conn.execute("SELECT * FROM members WHERE id=?", (member_id,)).fetchone()
    return dict(row) if row else None


PAYMENT_SELECT = """
    SELECT p.*, m.name AS live_name, m.id AS live_id
    FROM payments p
    LEFT JOIN members m ON m.id = p.member_id
"""


def payment_dict(r):
    return {
        "id": r["id"],
        "member_id": r["member_id"],
        # live name if the member still exists; otherwise the name saved with the payment
        "name": r["live_name"] or r["payer_name"] or "Walk-in",
        "member_removed": bool(r["member_id"] and not r["live_id"]),
        "membership_id": r["membership_id"],
        "category": r["category"],
        "category_label": CATEGORIES.get(r["category"], r["category"]),
        "amount": r["amount"],
        "method": r["method"],
        "method_label": METHODS.get(r["method"], r["method"]),
        "paid_on": r["paid_on"],
        "note": r["note"] or "",
        "created_at": r["created_at"],
    }


def member_detail(conn, member_id):
    """The full profile: member + money summary + every membership period + every payment."""
    rows = fetch_members(conn, "WHERE m.id = ?", (member_id,))
    if not rows:
        return None
    m = rows[0]

    periods = []
    for p in conn.execute(
        """SELECT s.*, COALESCE((SELECT SUM(amount) FROM payments WHERE membership_id = s.id), 0) AS paid
           FROM memberships s WHERE s.member_id = ? ORDER BY s.expiry DESC, s.id DESC""",
        (member_id,),
    ).fetchall():
        periods.append({
            "id": p["id"],
            "plan": p["plan"],
            "plan_label": plan_label(p["plan"], p["start"], p["expiry"]),
            "start": p["start"],
            "expiry": p["expiry"],
            "price": p["price"],
            "paid": p["paid"],
            "balance": max(0, p["price"] - p["paid"]),
            "note": p["note"] or "",
            "created_at": p["created_at"],
        })
    for i, p in enumerate(periods):
        p["is_latest"] = (i == 0)
        p["can_undo"] = (i == 0 and len(periods) > 1)

    payments = [
        payment_dict(r)
        for r in conn.execute(PAYMENT_SELECT + " WHERE p.member_id = ? ORDER BY p.paid_on DESC, p.id DESC", (member_id,)).fetchall()
    ]
    m["memberships"] = periods
    m["payments"] = payments
    return m


def list_prices(conn):
    prices = {"male": {}, "female": {}}
    for r in conn.execute("SELECT gender, months, price FROM plan_prices").fetchall():
        prices.setdefault(r["gender"], {})[r["months"]] = r["price"]
    return prices


def list_price(conn, gender, plan):
    row = conn.execute("SELECT price FROM plan_prices WHERE gender=? AND months=?", (gender, str(plan))).fetchone()
    return row["price"] if row else 0


def resolve_price(conn, data, gender, plan):
    """The price charged for a period. If the form didn't send one, use the list price
    for that plan+gender (custom plans have no list price → 0)."""
    raw = data.get("price")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return list_price(conn, gender, plan)
    return parse_amount(raw, "Price")


# ────────────────────────────────
# MEMBERS — validation + shared write helpers
# ────────────────────────────────

def clean_member_fields(data, creating):
    """Validates + normalises a member payload. Raises ApiError with a readable message."""
    name = clean_text(data.get("name"), 80, "Name")
    phone = re.sub(r"\D", "", str(data.get("phone", "")))[-10:]
    gender = data.get("gender")
    plan = str(data.get("plan", ""))

    if not name:
        raise ApiError("Name is required.")
    if len(phone) != 10:
        raise ApiError("Enter a valid 10-digit phone number.")
    if gender not in ("male", "female"):
        raise ApiError("Gender must be male or female.")
    if plan not in VALID_PLANS:
        raise ApiError("Unknown membership plan.")

    start = parse_date(data.get("start"), "Start date")
    expiry_raw = data.get("expiry")
    if expiry_raw in (None, ""):
        if plan == "0":
            raise ApiError("Pick the valid-till date for a custom plan.")
        if not creating:
            raise ApiError("Start and expiry dates are required.")
        expiry = plan_end(start, int(plan))          # auto-calculated from the plan
    else:
        expiry = parse_date(expiry_raw, "Expiry date")

    if expiry < start:
        raise ApiError("Expiry date can't be before the start date.")
    if expiry > today_ist() + timedelta(days=366 * 6):
        raise ApiError("Expiry date looks too far in the future — please check the year.")

    return {"name": name, "phone": phone, "gender": gender, "plan": plan, "start": start, "expiry": expiry}


def create_period(conn, member_id, plan, start, expiry, price, note=""):
    cur = conn.execute(
        "INSERT INTO memberships (member_id, plan, start, expiry, price, note, created_at) VALUES (?,?,?,?,?,?,?)",
        (member_id, plan, start.isoformat(), expiry.isoformat(), price, note or None, now_ist_str()),
    )
    return cur.lastrowid


def sync_member_from_periods(conn, member_id):
    """members.plan / members.expiry always mirror the LATEST period (the one that ends last).
    The reminder + filter code reads those two columns, so they must stay in step."""
    latest = conn.execute(
        "SELECT plan, expiry FROM memberships WHERE member_id=? ORDER BY expiry DESC, id DESC LIMIT 1", (member_id,)
    ).fetchone()
    if latest:
        conn.execute("UPDATE members SET plan=?, expiry=? WHERE id=?", (latest["plan"], latest["expiry"], member_id))


def insert_payment(conn, *, member_id, payer_name, membership_id, category, amount, method, paid_on, note):
    cur = conn.execute(
        """INSERT INTO payments (member_id, payer_name, membership_id, category, amount, method, paid_on, note, created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (member_id, payer_name or None, membership_id, category, amount, method, paid_on.isoformat(), note or None, now_ist_str()),
    )
    return cur.lastrowid


def duplicate_phone_error(phone, own_id=None):
    with read_conn() as conn:
        row = conn.execute("SELECT id, name FROM members WHERE phone=? AND id IS NOT ?", (phone, own_id)).fetchone()
    who = f" ({row['name']})" if row else ""
    msg = f"Another member already uses this phone number{who}." if own_id else f"A member with this phone number already exists{who}."
    return ApiError(msg, 409, code="duplicate_phone", existing_id=row["id"] if row else None)


# ────────────────────────────────
# MEMBERS — API
# ────────────────────────────────

@app.route("/api/bootstrap", methods=["GET"])
@login_required
def bootstrap():
    """Everything the admin needs to start up, in one request. `today` is the SERVER's
    (IST) date so the browser never disagrees with the reminder logic about what 'today' is."""
    with read_conn() as conn:
        members = fetch_members(conn)
        prices = list_prices(conn)
    return jsonify({
        "today": today_ist().isoformat(),
        "members": members,
        "plan_prices": prices,
        "categories": CATEGORIES,
        "methods": METHODS,
        "soon_days": SOON_DAYS,
        "meta_configured": bool(META_ACCESS_TOKEN and META_PHONE_NUMBER_ID),
        "revenue_pin_required": bool(REVENUE_PIN),
        "revenue_unlocked": revenue_unlocked(),
    })


@app.route("/api/members", methods=["GET"])
@login_required
def get_members():
    with read_conn() as conn:
        return jsonify(fetch_members(conn))


@app.route("/api/members/<member_id>", methods=["GET"])
@login_required
def get_member(member_id):
    with read_conn() as conn:
        detail = member_detail(conn, member_id)
    if not detail:
        raise ApiError("Member not found.", 404)
    return jsonify(detail)


@app.route("/api/members", methods=["POST"])
@login_required
def add_member():
    """Add a member AND their first membership period (+ first payment) in one go.
    Body: name, phone, gender, plan, start, [expiry], [price], [paid], [method], [paid_on], [note]"""
    payload = get_json_body()
    f = clean_member_fields(payload, creating=True)
    method = clean_choice(payload.get("method") or "cash", METHODS, "payment method")
    paid_on = payment_date(payload.get("paid_on"))
    note = clean_text(payload.get("note"), 200, "Note")
    new_id = "m_" + uuid.uuid4().hex[:10]

    try:
        with tx() as conn:
            price = resolve_price(conn, payload, f["gender"], f["plan"])
            paid = parse_amount(payload.get("paid"), "Amount paid", default=0)
            if paid > price:
                raise ApiError(f"Amount paid can't be more than the membership price (₹{price:,}).")

            conn.execute(
                "INSERT INTO members (id, name, phone, gender, plan, start, expiry) VALUES (?,?,?,?,?,?,?)",
                (new_id, f["name"], f["phone"], f["gender"], f["plan"], f["start"].isoformat(), f["expiry"].isoformat()),
            )
            period_id = create_period(conn, new_id, f["plan"], f["start"], f["expiry"], price, note)
            if paid > 0:
                insert_payment(conn, member_id=new_id, payer_name=f["name"], membership_id=period_id,
                               category="membership", amount=paid, method=method, paid_on=paid_on, note="")
            detail = member_detail(conn, new_id)
    except sqlite3.IntegrityError:
        raise duplicate_phone_error(f["phone"])

    return jsonify(detail), 201


@app.route("/api/members/<member_id>", methods=["PUT"])
@login_required
def update_member(member_id):
    """Edit = fix mistakes (name, phone, join date, plan, valid-till).
    To actually EXTEND a membership use /renew — it also records the payment."""
    payload = get_json_body()
    f = clean_member_fields(payload, creating=False)
    try:
        with tx() as conn:
            if not conn.execute("SELECT 1 FROM members WHERE id=?", (member_id,)).fetchone():
                raise ApiError("Member not found.", 404)

            periods = conn.execute(
                "SELECT id, start FROM memberships WHERE member_id=? ORDER BY expiry DESC, id DESC", (member_id,)
            ).fetchall()
            latest = periods[0] if periods else None
            only_one = len(periods) <= 1

            # The valid-till date can't end before the CURRENT period began.
            if latest and not only_one and f["expiry"] < date.fromisoformat(latest["start"]):
                raise ApiError(f"Valid-till can't be earlier than when the current period started ({format_date_display(latest['start'])}).")

            conn.execute(
                "UPDATE members SET name=?, phone=?, gender=?, plan=?, start=?, expiry=? WHERE id=?",
                (f["name"], f["phone"], f["gender"], f["plan"], f["start"].isoformat(), f["expiry"].isoformat(), member_id),
            )
            if latest:
                # With a single period, "joined on" IS that period's start. With several, only plan + end change.
                new_start = f["start"].isoformat() if only_one else latest["start"]
                conn.execute("UPDATE memberships SET plan=?, start=?, expiry=? WHERE id=?",
                             (f["plan"], new_start, f["expiry"].isoformat(), latest["id"]))
            else:
                create_period(conn, member_id, f["plan"], f["start"], f["expiry"], 0, "Existing member — no payment recorded")
            detail = member_detail(conn, member_id)
    except sqlite3.IntegrityError:
        raise duplicate_phone_error(f["phone"], own_id=member_id)
    return jsonify(detail)


@app.route("/api/members/<member_id>", methods=["DELETE"])
@login_required
def delete_member(member_id):
    """Removes the member and their membership periods. Their PAYMENTS are kept —
    money that was received is still revenue (each payment keeps the member's name)."""
    with tx() as conn:
        conn.execute("DELETE FROM memberships WHERE member_id=?", (member_id,))
        conn.execute("DELETE FROM members WHERE id=?", (member_id,))
    return jsonify({"deleted": member_id})


@app.route("/api/members/<member_id>/renew", methods=["POST"])
@login_required
def renew_member(member_id):
    """Renew / extend a membership.
    Body: plan, [start], [expiry | days], [price], [paid], [method], [paid_on], [note]
      • start defaults to the day after the current expiry if still valid, otherwise today
      • price defaults to the plan's list price; paid defaults to 0 (the rest becomes dues)"""
    payload = get_json_body()
    plan = str(payload.get("plan", ""))
    if plan not in VALID_PLANS:
        raise ApiError("Pick a membership plan.")
    method = clean_choice(payload.get("method") or "cash", METHODS, "payment method")
    paid_on = payment_date(payload.get("paid_on"))
    note = clean_text(payload.get("note"), 200, "Note")

    with tx() as conn:
        m = conn.execute("SELECT * FROM members WHERE id=?", (member_id,)).fetchone()
        if not m:
            raise ApiError("Member not found.", 404)

        today = today_ist()
        current_expiry = date.fromisoformat(m["expiry"])
        if payload.get("start") in (None, ""):
            start = current_expiry + timedelta(days=1) if current_expiry >= today else today
        else:
            start = parse_date(payload.get("start"), "Start date")

        if payload.get("expiry") not in (None, ""):
            end = parse_date(payload.get("expiry"), "Valid-till date")
        elif plan == "0":
            try:
                days = int(payload.get("days"))
            except (TypeError, ValueError):
                raise ApiError("For a custom length, enter the number of days or a valid-till date.")
            if not 1 <= days <= 3660:
                raise ApiError("Custom length must be between 1 and 3660 days.")
            end = start + timedelta(days=days - 1)
        else:
            end = plan_end(start, int(plan))

        if end < start:
            raise ApiError("Valid-till can't be before the start date.")
        if end > today + timedelta(days=366 * 6):
            raise ApiError("Valid-till looks too far in the future — please check the dates.")

        price = resolve_price(conn, payload, m["gender"], plan)
        paid = parse_amount(payload.get("paid"), "Amount paid", default=0)
        if paid > price:
            raise ApiError(f"Amount paid can't be more than the price (₹{price:,}).")

        period_id = create_period(conn, member_id, plan, start, end, price, note)
        sync_member_from_periods(conn, member_id)
        if paid > 0:
            insert_payment(conn, member_id=member_id, payer_name=m["name"], membership_id=period_id,
                           category="membership", amount=paid, method=method, paid_on=paid_on, note="")
        detail = member_detail(conn, member_id)
    return jsonify(detail)


@app.route("/api/memberships/<int:period_id>", methods=["PUT"])
@login_required
def update_membership(period_id):
    """Correct the price (or note) of one membership period, e.g. a discount entered wrongly."""
    payload = get_json_body()
    with tx() as conn:
        p = conn.execute("SELECT * FROM memberships WHERE id=?", (period_id,)).fetchone()
        if not p:
            raise ApiError("Membership period not found.", 404)
        price = parse_amount(payload.get("price"), "Price") if "price" in payload else p["price"]
        note = clean_text(payload.get("note"), 200, "Note") if "note" in payload else (p["note"] or "")
        paid = conn.execute("SELECT COALESCE(SUM(amount),0) AS s FROM payments WHERE membership_id=?", (period_id,)).fetchone()["s"]
        if price < paid:
            raise ApiError(f"₹{paid:,} is already paid for this period, so the price can't be lower than that.")
        conn.execute("UPDATE memberships SET price=?, note=? WHERE id=?", (price, note or None, period_id))
        detail = member_detail(conn, p["member_id"])
    return jsonify(detail)


@app.route("/api/memberships/<int:period_id>", methods=["DELETE"])
@login_required
def undo_membership(period_id):
    """Undo a renewal done by mistake. Only the LATEST period can be undone; payments
    recorded against it are removed too (the admin confirms this first)."""
    with tx() as conn:
        p = conn.execute("SELECT * FROM memberships WHERE id=?", (period_id,)).fetchone()
        if not p:
            raise ApiError("Membership period not found.", 404)
        periods = conn.execute(
            "SELECT id FROM memberships WHERE member_id=? ORDER BY expiry DESC, id DESC", (p["member_id"],)
        ).fetchall()
        if len(periods) < 2:
            raise ApiError("This is the member's only membership — edit it instead, or delete the member.")
        if periods[0]["id"] != period_id:
            raise ApiError("Only the most recent renewal can be undone.")

        linked = conn.execute("SELECT COUNT(*) AS c FROM payments WHERE membership_id=?", (period_id,)).fetchone()["c"]
        if linked and not revenue_unlocked():
            raise ApiError("Revenue is locked. Enter the revenue PIN first.", 403, code="revenue_locked")

        conn.execute("DELETE FROM payments WHERE membership_id=?", (period_id,))
        conn.execute("DELETE FROM memberships WHERE id=?", (period_id,))
        sync_member_from_periods(conn, p["member_id"])
        detail = member_detail(conn, p["member_id"])
    return jsonify(detail)


@app.route("/api/members/expiring/<int:days>", methods=["GET"])
@login_required
def get_expiring_members(days):
    """Members whose membership ends within the next `days` days (today included)."""
    with read_conn() as conn:
        members = fetch_members(conn)
    result = [m for m in members if 0 <= m["days_left"] <= days]
    result.sort(key=lambda m: m["days_left"])
    return jsonify(result)


@app.route("/api/members/filter", methods=["GET"])
@login_required
def filter_members():
    """Flexible member filter for the Broadcast panel (gender, status, plan, tenure — any combination)."""
    gender = request.args.get("gender")                           # "male" | "female" | None
    status = request.args.get("status")                           # "active" | "soon" | "expired" | None
    plan = request.args.get("plan")                               # "1" | "3" | "6" | "12" | None
    min_tenure = request.args.get("min_tenure_months", type=int)
    max_tenure = request.args.get("max_tenure_months", type=int)

    with read_conn() as conn:
        members = fetch_members(conn)

    result = []
    for m in members:
        if gender and m["gender"] != gender:
            continue
        if status and m["status"] != status:
            continue
        if plan and m["plan"] != plan:
            continue
        if min_tenure is not None and m["tenure_months"] < min_tenure:
            continue
        if max_tenure is not None and m["tenure_months"] > max_tenure:
            continue
        result.append(m)
    return jsonify(result)


# ────────────────────────────────
# PAYMENTS — recording money received
# ────────────────────────────────

def allocate_dues(conn, member_id, amount):
    """Spread a membership payment over the member's unpaid periods, OLDEST FIRST.
    Returns [(period_id, chunk), ...]. Normally that's one period; if the amount
    covers two, it becomes two rows so every period's 'paid' stays exact."""
    periods = conn.execute(
        """SELECT s.id, s.price,
                  COALESCE((SELECT SUM(amount) FROM payments WHERE membership_id = s.id), 0) AS paid
           FROM memberships s WHERE s.member_id = ? ORDER BY s.start ASC, s.id ASC""",
        (member_id,),
    ).fetchall()

    chunks, left, total_due = [], amount, 0
    for p in periods:
        remaining = p["price"] - p["paid"]
        if remaining <= 0:
            continue
        total_due += remaining
        take = min(remaining, left)
        if take > 0:
            chunks.append((p["id"], take))
            left -= take

    if total_due == 0:
        raise ApiError("This member has no membership dues. Use Renew to add a new membership period, "
                       "or record this under Trainer fees / Items sold / Other.")
    if left > 0:
        raise ApiError(f"Only ₹{total_due:,} is due for this member's membership. Enter ₹{total_due:,} or less.")
    return chunks


@app.route("/api/payments", methods=["POST"])
@login_required
def add_payment():
    """Record money received.
    Body: category, amount, [method], [paid_on], [note], [member_id], [payer_name]
      • category "membership" must have a member_id and is applied to that member's dues
      • other categories may be linked to a member, or left as a walk-in sale"""
    payload = get_json_body()
    category = clean_choice(payload.get("category"), CATEGORIES, "category")
    method = clean_choice(payload.get("method") or "cash", METHODS, "payment method")
    amount = parse_amount(payload.get("amount"), "Amount", allow_zero=False)
    paid_on = payment_date(payload.get("paid_on"))
    note = clean_text(payload.get("note"), 200, "Note")
    payer = clean_text(payload.get("payer_name"), 80, "Name")
    member_id = payload.get("member_id") or None

    with tx() as conn:
        member = None
        if member_id:
            member = conn.execute("SELECT id, name FROM members WHERE id=?", (member_id,)).fetchone()
            if not member:
                raise ApiError("Member not found.", 404)

        created = []
        if category == "membership":
            if not member:
                raise ApiError("Membership fees must be linked to a member.")
            for period_id, chunk in allocate_dues(conn, member["id"], amount):
                created.append(insert_payment(conn, member_id=member["id"], payer_name=member["name"], membership_id=period_id,
                                              category=category, amount=chunk, method=method, paid_on=paid_on, note=note))
        else:
            created.append(insert_payment(conn, member_id=member["id"] if member else None,
                                          payer_name=member["name"] if member else payer, membership_id=None,
                                          category=category, amount=amount, method=method, paid_on=paid_on, note=note))
        detail = member_detail(conn, member["id"]) if member else None

    return jsonify({"created": created, "member": detail}), 201


@app.route("/api/payments/<int:payment_id>", methods=["PUT"])
@login_required
@revenue_required
def update_payment(payment_id):
    """Fix a wrong entry (amount, method, date, note — and the type, for non-membership income)."""
    payload = get_json_body()
    with tx() as conn:
        p = conn.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
        if not p:
            raise ApiError("Payment not found.", 404)

        amount = parse_amount(payload.get("amount", p["amount"]), "Amount", allow_zero=False)
        method = clean_choice(payload.get("method", p["method"]), METHODS, "payment method")
        paid_on = payment_date(payload.get("paid_on", p["paid_on"]))
        note = clean_text(payload.get("note", p["note"]), 200, "Note")
        category = clean_choice(payload.get("category", p["category"]), CATEGORIES, "category")

        if (category == "membership") != (p["category"] == "membership"):
            raise ApiError("A membership payment can't be turned into another type (or the other way round). "
                           "Delete it and record it again instead.")

        if p["membership_id"]:
            period = conn.execute("SELECT price FROM memberships WHERE id=?", (p["membership_id"],)).fetchone()
            others = conn.execute("SELECT COALESCE(SUM(amount),0) AS s FROM payments WHERE membership_id=? AND id<>?",
                                  (p["membership_id"], payment_id)).fetchone()["s"]
            if period and others + amount > period["price"]:
                raise ApiError(f"That would be more than the membership price (₹{period['price']:,}). Edit the price first.")

        conn.execute("UPDATE payments SET category=?, amount=?, method=?, paid_on=?, note=? WHERE id=?",
                     (category, amount, method, paid_on.isoformat(), note or None, payment_id))
        row = conn.execute(PAYMENT_SELECT + " WHERE p.id = ?", (payment_id,)).fetchone()
        detail = member_detail(conn, p["member_id"]) if p["member_id"] else None
    return jsonify({"payment": payment_dict(row), "member": detail})


@app.route("/api/payments/<int:payment_id>", methods=["DELETE"])
@login_required
@revenue_required
def delete_payment(payment_id):
    with tx() as conn:
        p = conn.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
        if not p:
            raise ApiError("Payment not found.", 404)
        conn.execute("DELETE FROM payments WHERE id=?", (payment_id,))
        detail = member_detail(conn, p["member_id"]) if p["member_id"] else None
    return jsonify({"deleted": payment_id, "member": detail})


def _escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.route("/api/payments", methods=["GET"])
@login_required
@revenue_required
def list_payments():
    """Gym-wide transactions. Filters: from, to, category, method, q (name/note), member_id; paging: limit, offset."""
    where, params = [], []
    frm, to = request.args.get("from"), request.args.get("to")
    if frm:
        where.append("p.paid_on >= ?"); params.append(parse_date(frm, "From date").isoformat())
    if to:
        where.append("p.paid_on <= ?"); params.append(parse_date(to, "To date").isoformat())
    category, method = request.args.get("category"), request.args.get("method")
    if category:
        where.append("p.category = ?"); params.append(clean_choice(category, CATEGORIES, "category"))
    if method:
        where.append("p.method = ?"); params.append(clean_choice(method, METHODS, "payment method"))
    if request.args.get("member_id"):
        where.append("p.member_id = ?"); params.append(request.args["member_id"])
    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{_escape_like(q)}%"
        where.append("(COALESCE(m.name, p.payer_name, '') LIKE ? ESCAPE '\\' OR COALESCE(p.note, '') LIKE ? ESCAPE '\\')")
        params += [like, like]

    clause = ("WHERE " + " AND ".join(where)) if where else ""
    limit = max(1, min(request.args.get("limit", 50, type=int), 100000))
    offset = max(0, request.args.get("offset", 0, type=int))

    with read_conn() as conn:
        agg = conn.execute(
            f"SELECT COUNT(*) AS c, COALESCE(SUM(p.amount),0) AS s FROM payments p LEFT JOIN members m ON m.id = p.member_id {clause}",
            params).fetchone()
        rows = conn.execute(f"{PAYMENT_SELECT} {clause} ORDER BY p.paid_on DESC, p.id DESC LIMIT ? OFFSET ?",
                            params + [limit, offset]).fetchall()
    return jsonify({"items": [payment_dict(r) for r in rows], "count": agg["c"], "total": agg["s"]})


# ────────────────────────────────
# REVENUE — summary for a date range
# ────────────────────────────────

def range_totals(conn, frm, to):
    f, t = frm.isoformat(), to.isoformat()
    by_category = {k: {"amount": 0, "count": 0} for k in CATEGORIES}
    by_method = {k: {"amount": 0, "count": 0} for k in METHODS}
    for r in conn.execute("SELECT category, SUM(amount) AS a, COUNT(*) AS c FROM payments WHERE paid_on BETWEEN ? AND ? GROUP BY category", (f, t)):
        by_category[r["category"]] = {"amount": r["a"], "count": r["c"]}
    for r in conn.execute("SELECT method, SUM(amount) AS a, COUNT(*) AS c FROM payments WHERE paid_on BETWEEN ? AND ? GROUP BY method", (f, t)):
        by_method[r["method"]] = {"amount": r["a"], "count": r["c"]}
    return {
        "from": f, "to": t,
        "total": sum(v["amount"] for v in by_category.values()),
        "count": sum(v["count"] for v in by_category.values()),
        "by_category": by_category,
        "by_method": by_method,
    }


def build_series(conn, frm, to):
    """Chart data: one point per day (ranges up to ~3 months) or per month (longer ranges),
    zero-filled so the chart has no gaps. Each point is split by category for stacked bars."""
    daily = ((to - frm).days + 1) <= 92
    key_expr = "paid_on" if daily else "substr(paid_on, 1, 7)"
    data = {}
    for r in conn.execute(
        f"SELECT {key_expr} AS k, category, SUM(amount) AS a FROM payments WHERE paid_on BETWEEN ? AND ? GROUP BY k, category",
        (frm.isoformat(), to.isoformat()),
    ):
        data.setdefault(r["k"], {})[r["category"]] = r["a"]

    keys = []
    if daily:
        d = frm
        while d <= to:
            keys.append(d.isoformat())
            d += timedelta(days=1)
    else:
        y, m = frm.year, frm.month
        while (y, m) <= (to.year, to.month):
            keys.append(f"{y:04d}-{m:02d}")
            y, m = (y + 1, 1) if m == 12 else (y, m + 1)

    points = []
    for k in keys:
        cats = {c: data.get(k, {}).get(c, 0) for c in CATEGORIES}
        points.append({"key": k, "total": sum(cats.values()), "by_category": cats})
    return {"granularity": "day" if daily else "month", "points": points}


@app.route("/api/revenue/summary", methods=["GET"])
@login_required
@revenue_required
def revenue_summary():
    """Everything the Revenue page needs for one date range.
    Query: from, to (inclusive, YYYY-MM-DD), optional compare_from + compare_to."""
    frm = parse_date(request.args.get("from"), "From date")
    to = parse_date(request.args.get("to"), "To date")
    if to < frm:
        raise ApiError("'To' date can't be before the 'From' date.")
    if (to - frm).days > 366 * 5:
        raise ApiError("Please pick a range of 5 years or less.")

    compare = None
    if request.args.get("compare_from") and request.args.get("compare_to"):
        cfrom = parse_date(request.args["compare_from"], "Compare from")
        cto = parse_date(request.args["compare_to"], "Compare to")
        if cto >= cfrom:
            compare = (cfrom, cto)

    with read_conn() as conn:
        current = range_totals(conn, frm, to)
        previous = range_totals(conn, *compare) if compare else None
        series = build_series(conn, frm, to)

        first_period = "s.id = (SELECT MIN(id) FROM memberships WHERE member_id = s.member_id)"
        joinings = conn.execute(f"SELECT COUNT(*) AS c FROM memberships s WHERE s.start BETWEEN ? AND ? AND {first_period}",
                                (frm.isoformat(), to.isoformat())).fetchone()["c"]
        renewals = conn.execute(f"SELECT COUNT(*) AS c FROM memberships s WHERE s.start BETWEEN ? AND ? AND NOT ({first_period})",
                                (frm.isoformat(), to.isoformat())).fetchone()["c"]

        dues = [
            {"id": m["id"], "name": m["name"], "phone": m["phone"], "due": m["due"], "expiry": m["expiry"], "status": m["status"]}
            for m in fetch_members(conn) if m["due"] > 0
        ]
        dues.sort(key=lambda d: -d["due"])

    return jsonify({
        "current": current,
        "previous": previous,
        "series": series,
        "joinings": joinings,
        "renewals": renewals,
        "dues": {"total": sum(d["due"] for d in dues), "count": len(dues), "members": dues[:50]},
    })


# ────────────────────────────────
# REVENUE LOCK (optional PIN)
# ────────────────────────────────

@app.route("/api/revenue/status", methods=["GET"])
@login_required
def revenue_status():
    return jsonify({"pin_required": bool(REVENUE_PIN), "unlocked": revenue_unlocked()})


@app.route("/api/revenue/unlock", methods=["POST"])
@login_required
def revenue_unlock():
    if not REVENUE_PIN:
        return jsonify({"ok": True})
    if is_throttled("pin"):
        return jsonify({"error": "Too many attempts. Please wait a few minutes and try again."}), 429
    pin = str((request.get_json(silent=True) or {}).get("pin", "")).strip()
    if pin and secure_equals(pin, REVENUE_PIN):
        clear_failures("pin")
        session["revenue_unlocked"] = True
        return jsonify({"ok": True})
    record_failure("pin")
    # 403, not 401: the admin session is still valid — only the extra PIN was wrong.
    # (A 401 would make the admin page think the login expired and log the user out.)
    return jsonify({"error": "Incorrect PIN.", "code": "bad_pin"}), 403


@app.route("/api/revenue/lock", methods=["POST"])
@login_required
def revenue_lock():
    session.pop("revenue_unlocked", None)
    return jsonify({"ok": True})


# ────────────────────────────────
# SETTINGS + BACKUP
# ────────────────────────────────

@app.route("/api/settings/plan-prices", methods=["GET"])
@login_required
def get_plan_prices():
    with read_conn() as conn:
        return jsonify(list_prices(conn))


@app.route("/api/settings/plan-prices", methods=["PUT"])
@login_required
def set_plan_prices():
    """Body: {"male": {"1": 1000, "3": 2500, ...}, "female": {...}}. Only affects NEW memberships."""
    payload = get_json_body()
    clean = []
    for gender in ("male", "female"):
        for months, raw in (payload.get(gender) or {}).items():
            if str(months) not in ("1", "3", "6", "12"):
                raise ApiError("Unknown plan length.")
            clean.append((gender, str(months), parse_amount(raw, f"{gender.title()} {months}-month price", allow_zero=False)))
    if not clean:
        raise ApiError("No prices were sent.")
    with tx() as conn:
        conn.executemany("INSERT OR REPLACE INTO plan_prices (gender, months, price) VALUES (?,?,?)", clean)
        prices = list_prices(conn)
    return jsonify(prices)


@app.route("/api/backup", methods=["GET"])
@login_required
@revenue_required
def download_backup():
    """A consistent snapshot of the whole database as one file.
    Free hosts often wipe local files on redeploy — download one of these now and then."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    src, dst = get_db(), sqlite3.connect(tmp.name)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    resp = send_file(tmp.name, as_attachment=True, download_name=f"xgym-backup-{today_ist().isoformat()}.db")
    resp.call_on_close(lambda: os.path.exists(tmp.name) and os.unlink(tmp.name))
    return resp


def inspect_backup(path):
    """Checks that an uploaded file really is an X GYM database and counts what's inside.
    Raises ApiError with a readable message if not. Never modifies the file."""
    conn = None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ApiError("That backup file is damaged (it failed the integrity check).")
        cols = get_existing_columns(conn, "members")
        if not cols or not REQUIRED_MEMBER_COLUMNS.issubset(cols):
            raise ApiError("That file isn't an X GYM backup (no members table found).")
        counts = {}
        for table in ("members", "memberships", "payments"):
            counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] if get_existing_columns(conn, table) else 0
        return counts
    except sqlite3.DatabaseError:
        raise ApiError("That file isn't a valid database. Choose a backup you downloaded from Settings.")
    finally:
        if conn:
            conn.close()


@app.route("/api/restore", methods=["POST"])
@login_required
@revenue_required
def restore_backup():
    """Replace ALL current data with an uploaded backup file.
    POST multipart form with field `file`. Add ?dry_run=1 first to just preview what's inside.
    A copy of the current database is kept as pre-restore-backup.db beside it."""
    upload = request.files.get("file")
    if not upload or not upload.filename:
        raise ApiError("Choose a backup file first.")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        upload.save(tmp.name)
        counts = inspect_backup(tmp.name)
        if request.args.get("dry_run"):
            return jsonify({"ok": True, "dry_run": True, "counts": counts})

        # safety copy of what's there right now
        safety = os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "pre-restore-backup.db")
        cur, safe = get_db(), sqlite3.connect(safety)
        try:
            cur.backup(safe)
        finally:
            safe.close()
            cur.close()

        # copy the uploaded database over the live one (same file path, so nothing else needs to change)
        src, dst = sqlite3.connect(tmp.name), get_db()
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
        init_db()          # older backups: add any newer tables/columns and fill in missing membership periods
        return jsonify({"ok": True, "counts": counts})
    finally:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)


# ────────────────────────────────
# WHATSAPP (Meta Cloud API) — reminders + broadcasts
# ────────────────────────────────

def build_reminder_variables(name, expiry_str, days_left):
    """
    Builds the {{1}}, {{2}}, {{3}} values for the approved
    'gym_membership_reminder' Content Template:
    "Hi {{1}}, this is X GYM Mahipalpur. Your membership is expiring {{2}} ({{3}}).
     To renew, please call or WhatsApp us directly at +91 98105 03912 — this number is for reminders only."
    """
    first_name = name.strip().split(" ")[0]
    expiry_fmt = format_date_display(expiry_str)
    if days_left <= 0:
        urgency = "today"
    elif days_left == 1:
        urgency = "tomorrow"
    else:
        urgency = f"in {days_left} days"

    return {"1": first_name, "2": urgency, "3": expiry_fmt}


def already_reminded_today(member_id):
    with read_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM reminders WHERE member_id=? AND sent_date=? AND status='sent'",
            (member_id, today_ist().isoformat())
        ).fetchone()
    return row is not None


def log_reminder(member_id, days_left, status, error=None):
    with tx() as conn:
        conn.execute(
            "INSERT INTO reminders (member_id, sent_date, days_left, status, error) VALUES (?,?,?,?,?)",
            (member_id, today_ist().isoformat(), days_left, status, error)
        )


def log_broadcast(member_id, template_name, status, error=None):
    with tx() as conn:
        conn.execute(
            "INSERT INTO broadcast_log (member_id, template_name, sent_date, status, error) VALUES (?,?,?,?,?)",
            (member_id, template_name, today_ist().isoformat(), status, error)
        )


def send_whatsapp_template_generic(phone_10digit, template_name, body_variables, media_url=None, media_type=None):
    """
    Sends ANY approved template — the reminder, an announcement, or future
    ones you add to AVAILABLE_TEMPLATES. body_variables is an ordered list
    filling {{1}}, {{2}}, {{3}}... in the template body.
    If media_url + media_type are given, adds a media header component
    (required for templates built with a video/image header).
    """
    if not META_ACCESS_TOKEN or not META_PHONE_NUMBER_ID:
        raise RuntimeError("Meta WhatsApp credentials not set (check .env)")

    url = f"https://graph.facebook.com/v20.0/{META_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {META_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    components = []
    if media_url and media_type:
        components.append({
            "type": "header",
            "parameters": [{"type": media_type, media_type: {"link": media_url}}]
        })
    components.append({
        "type": "body",
        "parameters": [{"type": "text", "text": v} for v in body_variables]
    })

    payload = {
        "messaging_product": "whatsapp",
        "to": f"91{phone_10digit}",
        "type": "template",
        "template": {
            "name": template_name,
            "language": {"code": "en"},
            "components": components
        }
    }

    res = requests.post(url, headers=headers, json=payload, timeout=15)
    if res.status_code >= 400:
        raise RuntimeError(f"Meta API error {res.status_code}: {res.text}")

    return res.json().get("messages", [{}])[0].get("id")


@app.route("/api/templates", methods=["GET"])
@login_required
def list_templates():
    return jsonify(AVAILABLE_TEMPLATES)


@app.route("/api/broadcast/send", methods=["POST"])
@login_required
def send_broadcast():
    """Send an approved template to a chosen set of members."""
    data = get_json_body()
    member_ids = data.get("member_ids") or []
    template_name = data.get("template_name")
    extra_variables = [str(v) for v in (data.get("extra_variables") or [])]   # fills {{2}}, {{3}}... same for every recipient
    media_url = (data.get("media_url") or "").strip() or None

    if not isinstance(member_ids, list) or not member_ids:
        raise ApiError("Select at least one member.")
    if len(member_ids) > 1000:
        raise ApiError("Too many recipients in one go (max 1000).")

    template_config = AVAILABLE_TEMPLATES.get(template_name)
    if not template_config:
        raise ApiError(f"Unknown template '{template_name}'. Check AVAILABLE_TEMPLATES in app.py.")

    # Video/image is a CHOICE, not compulsory — if the admin leaves the URL blank,
    # the broadcast is simply sent without a media header. Note: if this template
    # was itself built in Meta's Template Builder WITH a mandatory media header,
    # Meta's API will reject a send that has no media — that's a Meta-side
    # constraint, not something this app can override. If you want broadcasts to
    # always be sendable with or without a video, approve a text-only template
    # (has_media: False) alongside your video template and let the admin pick.
    media_type = template_config.get("media_type") if (template_config.get("has_media") and media_url) else None

    sent, failed = [], []
    for member_id in member_ids:
        member = get_member_row(member_id)
        if not member:
            failed.append({"id": member_id, "reason": "Member not found"})
            continue

        first_name = member["name"].strip().split(" ")[0]
        body_variables = [first_name] + extra_variables
        try:
            send_whatsapp_template_generic(member["phone"], template_name, body_variables, media_url, media_type)
            log_broadcast(member_id, template_name, "sent")
            sent.append(member_id)
        except Exception as e:
            log_broadcast(member_id, template_name, "failed", str(e))
            failed.append({"id": member_id, "name": member["name"], "reason": str(e)})

    return jsonify({"sent": sent, "failed": failed})


@app.route("/api/reminders/send-bulk", methods=["POST"])
@login_required
def send_bulk_reminders():
    """Manual bulk send (the 'Send reminders' button). Only for members who haven't expired yet —
    the approved template says 'expiring …', which would be wrong for someone already expired."""
    data = get_json_body()
    member_ids = data.get("member_ids") or []
    if not isinstance(member_ids, list) or not member_ids:
        raise ApiError("Select at least one member.")

    sent, failed = [], []
    for member_id in member_ids:
        member = get_member_row(member_id)
        if not member:
            failed.append({"id": member_id, "reason": "Member not found"})
            continue

        days_left = days_until(member["expiry"])
        if days_left < 0:
            failed.append({"id": member_id, "name": member["name"],
                           "reason": "Already expired — message them manually on WhatsApp instead."})
            continue

        variables = build_reminder_variables(member["name"], member["expiry"], days_left)
        body_variables = [variables["1"], variables["2"], variables["3"]]
        try:
            send_whatsapp_template_generic(member["phone"], META_TEMPLATE_NAME, body_variables)
            log_reminder(member_id, days_left, "sent")
            sent.append(member_id)
        except Exception as e:
            log_reminder(member_id, days_left, "failed", str(e))
            failed.append({"id": member_id, "name": member["name"], "reason": str(e)})

    return jsonify({"sent": sent, "failed": failed})


# ────────────────────────────────
# Daily automated check, triggered by an external cron service.
# Protected by a shared secret header so randoms can't trigger mass-sends.
# ────────────────────────────────

@app.route("/api/reminders/check-tomorrow", methods=["POST"])
def check_tomorrow():
    provided_secret = request.headers.get("X-CRON-SECRET", "")
    if not secure_equals(provided_secret, CRON_SECRET):
        return jsonify({"error": "Unauthorized"}), 403

    with read_conn() as conn:
        rows = conn.execute("SELECT * FROM members").fetchall()

    sent, skipped, failed = [], [], []

    for r in rows:
        member = dict(r)
        days_left = days_until(member["expiry"])

        if days_left != 1:
            continue  # only members expiring EXACTLY tomorrow

        if already_reminded_today(member["id"]):
            skipped.append(member["id"])
            continue

        variables = build_reminder_variables(member["name"], member["expiry"], days_left)
        body_variables = [variables["1"], variables["2"], variables["3"]]
        try:
            send_whatsapp_template_generic(member["phone"], META_TEMPLATE_NAME, body_variables)
            log_reminder(member["id"], days_left, "sent")
            sent.append(member["id"])
        except Exception as e:
            log_reminder(member["id"], days_left, "failed", str(e))
            failed.append({"id": member["id"], "reason": str(e)})

    return jsonify({"sent": sent, "skipped_already_sent": skipped, "failed": failed})


@app.route("/api/messages/log", methods=["GET"])
@login_required
def messages_log():
    """Recent automatic WhatsApp sends (reminders + broadcasts), newest first — so failures are visible."""
    limit = max(1, min(request.args.get("limit", 100, type=int), 500))
    with read_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM (
                   SELECT 'reminder' AS kind, r.id AS id, r.sent_date AS sent_date, r.status AS status, r.error AS error,
                          NULL AS template_name, r.days_left AS days_left, r.member_id AS member_id, m.name AS name, m.phone AS phone
                   FROM reminders r LEFT JOIN members m ON m.id = r.member_id
                   UNION ALL
                   SELECT 'broadcast', b.id, b.sent_date, b.status, b.error, b.template_name, NULL, b.member_id, m.name, m.phone
                   FROM broadcast_log b LEFT JOIN members m ON m.id = b.member_id
               ) ORDER BY sent_date DESC, id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "1") == "1", port=int(os.environ.get("PORT", 5000)))
