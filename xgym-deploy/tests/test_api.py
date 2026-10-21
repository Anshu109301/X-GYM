"""
Backend tests for the X GYM admin API.

Run from the project folder:
    python3 -m unittest discover -s tests -v

Uses a temporary database — your real xgym.db is never touched.
"""
import os
import sys
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta

# Must be set BEFORE importing app (app reads these at import time).
_TMP = tempfile.mkdtemp(prefix="xgym-test-")
os.environ["DB_PATH"] = os.path.join(_TMP, "test.db")
os.environ["ADMIN_PASSWORD"] = "test-password"
os.environ["SECRET_KEY"] = "test-secret"
os.environ.pop("REVENUE_PIN", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as gym  # noqa: E402


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def day(offset=0):
    """ISO date relative to today (IST, same clock the server uses)."""
    return (gym.today_ist() + timedelta(days=offset)).isoformat()


class Base(unittest.TestCase):
    def setUp(self):
        gym.REVENUE_PIN = ""
        gym._FAILS.clear()
        conn = sqlite3.connect(gym.DB_PATH)
        for table in ("payments", "memberships", "members", "reminders", "broadcast_log", "plan_prices"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()
        gym.init_db()                      # re-seeds default prices
        self.c = gym.app.test_client()
        self.login()

    def login(self):
        r = self.c.post("/api/login", json={"password": "test-password"})
        self.assertEqual(r.status_code, 200)

    # helpers ---------------------------------------------------------
    def add(self, name="Rahul Sharma", phone="9810000001", gender="male", plan="1", start=None, **extra):
        body = {"name": name, "phone": phone, "gender": gender, "plan": plan, "start": start or day(0)}
        body.update(extra)
        return self.c.post("/api/members", json=body)

    def member(self, mid):
        r = self.c.get(f"/api/members/{mid}")
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()

    def pay(self, **body):
        body.setdefault("method", "cash")
        return self.c.post("/api/payments", json=body)

    def summary(self, frm=None, to=None, **extra):
        q = {"from": frm or day(-30), "to": to or day(0)}
        q.update(extra)
        return self.c.get("/api/revenue/summary", query_string=q)


# ─────────────────────────────────────────────────────────────────────
class TestAuth(Base):
    def test_protected_routes_need_login(self):
        anon = gym.app.test_client()
        for url in ("/api/members", "/api/bootstrap", "/api/payments", "/api/revenue/summary", "/api/backup"):
            self.assertEqual(anon.get(url).status_code, 401, url)
        self.assertEqual(anon.post("/api/payments", json={}).status_code, 401)

    def test_wrong_password_and_throttle(self):
        anon = gym.app.test_client()
        self.assertEqual(anon.post("/api/login", json={"password": "nope"}).status_code, 401)
        for _ in range(gym.FAIL_LIMIT):
            anon.post("/api/login", json={"password": "nope"})
        # locked out now — even the right password is refused for the window
        self.assertEqual(anon.post("/api/login", json={"password": "test-password"}).status_code, 429)

    def test_security_headers(self):
        r = self.c.get("/api/members")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        admin = self.c.get("/admin")
        self.assertEqual(admin.headers["X-Frame-Options"], "DENY")
        self.assertEqual(admin.headers["Cache-Control"], "no-store")
        admin.close()
        self.assertEqual(self.c.get("/").status_code, 200)             # public site still served

    def test_api_errors_are_json(self):
        r = self.c.get("/api/does-not-exist")
        self.assertEqual(r.status_code, 404)
        self.assertIn("error", r.get_json())


# ─────────────────────────────────────────────────────────────────────
class TestAddMember(Base):
    def test_add_with_full_payment(self):
        r = self.add(price=1000, paid=1000, method="upi")
        self.assertEqual(r.status_code, 201, r.get_json())
        m = r.get_json()
        self.assertEqual(m["expiry"], gym.plan_end(gym.today_ist(), 1).isoformat())
        self.assertEqual((m["billed"], m["paid_total"], m["due"]), (1000, 1000, 0))
        self.assertEqual(len(m["memberships"]), 1)
        self.assertEqual(m["payments"][0]["method"], "upi")
        self.assertEqual(m["payments"][0]["category"], "membership")

    def test_default_price_comes_from_plan_prices(self):
        m = self.add(gender="female", plan="3").get_json()
        self.assertEqual(m["memberships"][0]["price"], 1500)          # women's 3-month list price
        m2 = self.add(phone="9810000002", gender="male", plan="12").get_json()
        self.assertEqual(m2["memberships"][0]["price"], 8500)

    def test_partial_payment_creates_dues(self):
        m = self.add(price=1000, paid=400).get_json()
        self.assertEqual(m["due"], 600)
        self.assertEqual(m["memberships"][0]["balance"], 600)

    def test_no_payment_means_full_due(self):
        m = self.add(price=1000).get_json()
        self.assertEqual((m["paid_total"], m["due"]), (0, 1000))
        self.assertEqual(m["payments"], [])

    def test_discount_is_just_a_lower_price(self):
        m = self.add(price=800, paid=800).get_json()
        self.assertEqual((m["billed"], m["due"]), (800, 0))

    def test_duplicate_phone_is_409_with_existing_id(self):
        first = self.add().get_json()
        r = self.add(name="Someone Else")
        self.assertEqual(r.status_code, 409)
        body = r.get_json()
        self.assertEqual(body["existing_id"], first["id"])
        self.assertIn("Rahul Sharma", body["error"])

    def test_phone_is_normalised_to_last_10_digits(self):
        m = self.add(phone="+91 98105-03912").get_json()
        self.assertEqual(m["phone"], "9810503912")

    def test_validation_errors(self):
        self.assertEqual(self.add(price=500, paid=600).status_code, 400)          # paid > price
        self.assertEqual(self.add(phone="123").status_code, 400)
        self.assertEqual(self.add(name="  ").status_code, 400)
        self.assertEqual(self.add(gender="x").status_code, 400)
        self.assertEqual(self.add(plan="7").status_code, 400)
        self.assertEqual(self.add(plan="0").status_code, 400)                      # custom needs an expiry
        self.assertEqual(self.add(price=-5).status_code, 400)
        self.assertEqual(self.add(price=12.5).status_code, 400)                    # whole rupees only
        self.assertEqual(self.add(price=99999999).status_code, 400)                # absurdly large
        self.assertEqual(self.add(method="bitcoin", price=100, paid=100).status_code, 400)
        self.assertEqual(self.add(expiry=day(-5)).status_code, 400)                # expiry before start
        self.assertEqual(self.c.get("/api/members").get_json(), [])                # nothing half-saved

    def test_custom_plan_with_explicit_expiry(self):
        m = self.add(plan="0", expiry=day(44), price=0).get_json()
        self.assertEqual(m["plan_label"], "Custom · 45 days")

    def test_failed_add_leaves_no_orphans(self):
        self.add(price=100, paid=100)
        self.add(phone="9810000001", price=100, paid=100)                          # dup phone → rolled back
        conn = sqlite3.connect(gym.DB_PATH)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM memberships").fetchone()[0], 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 1)


# ─────────────────────────────────────────────────────────────────────
class TestDates(unittest.TestCase):
    def test_plan_end_is_inclusive(self):
        self.assertEqual(gym.plan_end(date(2026, 10, 14), 1), date(2026, 11, 13))
        self.assertEqual(gym.plan_end(date(2026, 1, 1), 12), date(2026, 12, 31))
        self.assertEqual(gym.plan_end(date(2026, 10, 14), 3), date(2027, 1, 13))

    def test_month_end_clamps_instead_of_overflowing(self):
        self.assertEqual(gym.add_months(date(2026, 1, 31), 1), date(2026, 2, 28))
        self.assertEqual(gym.add_months(date(2028, 1, 31), 1), date(2028, 2, 29))   # leap year
        self.assertEqual(gym.add_months(date(2026, 8, 31), 6), date(2027, 2, 28))
        self.assertEqual(gym.add_months(date(2026, 12, 15), 2), date(2027, 2, 15))   # year rollover
        self.assertEqual(gym.add_months(date(2028, 2, 29), 12), date(2029, 2, 28))

    def test_status_thresholds(self):
        self.assertEqual(gym.status_for(-1), "expired")
        self.assertEqual(gym.status_for(0), "soon")
        self.assertEqual(gym.status_for(5), "soon")
        self.assertEqual(gym.status_for(6), "active")


# ─────────────────────────────────────────────────────────────────────
class TestRenew(Base):
    def test_renew_active_member_continues_from_expiry(self):
        m = self.add(start=day(-20), price=1000, paid=1000).get_json()           # expires in ~10 days
        old_expiry = date.fromisoformat(m["expiry"])
        r = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "3", "price": 2500, "paid": 2500, "method": "upi"})
        self.assertEqual(r.status_code, 200, r.get_json())
        d = r.get_json()
        new_start = old_expiry + timedelta(days=1)
        self.assertEqual(d["memberships"][0]["start"], new_start.isoformat())
        self.assertEqual(d["expiry"], gym.plan_end(new_start, 3).isoformat())
        self.assertEqual(d["plan"], "3")
        self.assertEqual(len(d["memberships"]), 2)
        self.assertEqual((d["billed"], d["paid_total"], d["due"]), (3500, 3500, 0))
        # list endpoint (which reminders/filters use) sees the new expiry too
        self.assertEqual(self.c.get("/api/members").get_json()[0]["expiry"], d["expiry"])

    def test_renew_expired_member_starts_today(self):
        m = self.add(start=day(-90), price=1000, paid=1000).get_json()           # long expired
        self.assertEqual(m["status"], "expired")
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "price": 1000, "paid": 1000}).get_json()
        self.assertEqual(d["memberships"][0]["start"], day(0))
        self.assertEqual(d["expiry"], gym.plan_end(gym.today_ist(), 1).isoformat())
        self.assertEqual(d["status"], "active")

    def test_renew_with_explicit_start_override(self):
        m = self.add(start=day(-90)).get_json()
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "start": day(10), "price": 0}).get_json()
        self.assertEqual(d["memberships"][0]["start"], day(10))

    def test_renew_custom_days_free_extension(self):
        m = self.add(price=1000, paid=1000).get_json()
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "0", "days": 7, "price": 0}).get_json()
        top = d["memberships"][0]
        self.assertEqual(top["price"], 0)
        self.assertEqual(top["plan_label"], "Custom · 7 days")
        self.assertEqual(d["due"], 0)

    def test_renew_partial_payment_adds_to_dues(self):
        m = self.add(price=1000, paid=1000).get_json()
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "6", "price": 4500, "paid": 1500}).get_json()
        self.assertEqual(d["due"], 3000)

    def test_renew_defaults_to_list_price(self):
        m = self.add(gender="female", price=600, paid=600).get_json()
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "6"}).get_json()
        self.assertEqual(d["memberships"][0]["price"], 2700)

    def test_renew_validation(self):
        m = self.add().get_json()
        url = f"/api/members/{m['id']}/renew"
        self.assertEqual(self.c.post(url, json={"plan": "9"}).status_code, 400)
        self.assertEqual(self.c.post(url, json={"plan": "1", "price": 100, "paid": 200}).status_code, 400)
        self.assertEqual(self.c.post(url, json={"plan": "0"}).status_code, 400)                    # custom needs days/expiry
        self.assertEqual(self.c.post(url, json={"plan": "0", "days": 0}).status_code, 400)
        self.assertEqual(self.c.post("/api/members/nope/renew", json={"plan": "1"}).status_code, 404)
        self.assertEqual(len(self.member(m["id"])["memberships"]), 1)                              # nothing saved

    def test_overlapping_renewal_never_shortens_membership(self):
        m = self.add(plan="12", price=0).get_json()                                                # ~1 year left
        before = m["expiry"]
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "start": day(0), "price": 0}).get_json()
        self.assertEqual(d["expiry"], before)

    def test_undo_latest_renewal_restores_previous_state(self):
        m = self.add(price=1000, paid=1000).get_json()
        original_expiry = m["expiry"]
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "3", "price": 2500, "paid": 2500}).get_json()
        self.assertNotEqual(d["expiry"], original_expiry)
        top = d["memberships"][0]
        self.assertTrue(top["can_undo"])
        u = self.c.delete(f"/api/memberships/{top['id']}")
        self.assertEqual(u.status_code, 200, u.get_json())
        back = u.get_json()
        self.assertEqual(back["expiry"], original_expiry)
        self.assertEqual(back["plan"], "1")
        self.assertEqual((back["billed"], back["paid_total"]), (1000, 1000))                       # its payment went too

    def test_cannot_undo_only_or_older_period(self):
        m = self.add(price=0).get_json()
        only = m["memberships"][0]["id"]
        self.assertEqual(self.c.delete(f"/api/memberships/{only}").status_code, 400)
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "price": 0}).get_json()
        self.assertEqual(self.c.delete(f"/api/memberships/{only}").status_code, 400)              # older one
        self.assertEqual(self.c.delete(f"/api/memberships/{d['memberships'][0]['id']}").status_code, 200)

    def test_edit_period_price(self):
        m = self.add(price=1000, paid=400).get_json()
        pid = m["memberships"][0]["id"]
        self.assertEqual(self.c.put(f"/api/memberships/{pid}", json={"price": 300}).status_code, 400)   # below what's paid
        d = self.c.put(f"/api/memberships/{pid}", json={"price": 900}).get_json()
        self.assertEqual(d["due"], 500)


# ─────────────────────────────────────────────────────────────────────
class TestPayments(Base):
    def test_collect_dues_in_instalments(self):
        m = self.add(price=1000, paid=300).get_json()
        r = self.pay(member_id=m["id"], category="membership", amount=200)
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(self.member(m["id"])["due"], 500)
        self.pay(member_id=m["id"], category="membership", amount=500)
        d = self.member(m["id"])
        self.assertEqual((d["due"], d["paid_total"]), (0, 1000))
        self.assertEqual(d["memberships"][0]["balance"], 0)

    def test_cannot_overpay_membership_or_pay_when_nothing_due(self):
        m = self.add(price=1000, paid=900).get_json()
        self.assertEqual(self.pay(member_id=m["id"], category="membership", amount=200).status_code, 400)
        self.pay(member_id=m["id"], category="membership", amount=100)
        r = self.pay(member_id=m["id"], category="membership", amount=1)
        self.assertEqual(r.status_code, 400)
        self.assertIn("no membership dues", r.get_json()["error"].lower())

    def test_payment_spanning_two_unpaid_periods_is_split_oldest_first(self):
        m = self.add(price=1000, paid=0).get_json()
        self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "price": 1000, "paid": 0})
        r = self.pay(member_id=m["id"], category="membership", amount=1500)
        self.assertEqual(len(r.get_json()["created"]), 2)
        d = r.get_json()["member"]
        self.assertEqual(d["due"], 500)
        oldest = d["memberships"][-1]
        self.assertEqual(oldest["balance"], 0)
        self.assertEqual(d["memberships"][0]["balance"], 500)

    def test_membership_payment_needs_a_member(self):
        self.assertEqual(self.pay(category="membership", amount=100).status_code, 400)

    def test_walk_in_sale_and_member_linked_sale(self):
        r = self.pay(category="products", amount=250, payer_name="Walk-in guy", note="Whey sachet", method="upi")
        self.assertEqual(r.status_code, 201)
        m = self.add(price=0).get_json()
        r2 = self.pay(member_id=m["id"], category="personal_training", amount=3000, note="PT - 1 month")
        self.assertEqual(r2.status_code, 201)
        d = self.member(m["id"])
        self.assertEqual(d["paid_total"], 3000)
        self.assertEqual(d["paid_membership"], 0)                       # PT fees are not membership dues
        self.assertEqual(d["due"], 0)

    def test_payment_validation(self):
        self.assertEqual(self.pay(category="products", amount=0).status_code, 400)
        self.assertEqual(self.pay(category="products", amount=-10).status_code, 400)
        self.assertEqual(self.pay(category="products", amount="abc").status_code, 400)
        self.assertEqual(self.pay(category="products", amount=10.5).status_code, 400)
        self.assertEqual(self.pay(category="nonsense", amount=10).status_code, 400)
        self.assertEqual(self.pay(category="products", amount=10, method="gold").status_code, 400)
        self.assertEqual(self.pay(category="products", amount=10, paid_on=day(3)).status_code, 400)   # future
        self.assertEqual(self.pay(category="products", amount=10, member_id="ghost").status_code, 404)
        self.assertEqual(self.pay(category="products", amount="1,250").status_code, 201)              # formatted input ok

    def test_edit_and_delete_payment(self):
        m = self.add(price=1000, paid=1000).get_json()
        pid = m["payments"][0]["id"]
        self.assertEqual(self.c.put(f"/api/payments/{pid}", json={"amount": 1200}).status_code, 400)   # > price
        r = self.c.put(f"/api/payments/{pid}", json={"amount": 800, "method": "card", "note": "fixed"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["member"]["due"], 200)
        self.assertEqual(self.c.put(f"/api/payments/{pid}", json={"category": "products"}).status_code, 400)
        d = self.c.delete(f"/api/payments/{pid}").get_json()
        self.assertEqual(d["member"]["due"], 1000)
        self.assertEqual(self.c.delete(f"/api/payments/{pid}").status_code, 404)

    def test_deleting_a_member_keeps_their_payments_in_revenue(self):
        m = self.add(name="Gone Guy", price=1000, paid=1000).get_json()
        self.assertEqual(self.c.delete(f"/api/members/{m['id']}").status_code, 200)
        items = self.c.get("/api/payments").get_json()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "Gone Guy")
        self.assertTrue(items[0]["member_removed"])
        self.assertEqual(self.summary().get_json()["current"]["total"], 1000)
        conn = sqlite3.connect(gym.DB_PATH)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM memberships").fetchone()[0], 0)


# ─────────────────────────────────────────────────────────────────────
class TestRevenue(Base):
    def seed(self):
        a = self.add(name="A", phone="9000000001", price=1000, paid=1000, method="cash").get_json()
        b = self.add(name="B", phone="9000000002", gender="female", plan="3", price=1500, paid=1000, method="upi").get_json()
        self.pay(category="personal_training", amount=3000, method="upi", member_id=a["id"])
        self.pay(category="products", amount=250, method="cash", payer_name="walk-in")
        self.pay(category="other", amount=100, method="card")
        return a, b

    def test_totals_by_category_and_method(self):
        self.seed()
        cur = self.summary().get_json()["current"]
        self.assertEqual(cur["total"], 1000 + 1000 + 3000 + 250 + 100)
        self.assertEqual(cur["count"], 5)
        c = cur["by_category"]
        self.assertEqual((c["membership"]["amount"], c["personal_training"]["amount"], c["products"]["amount"], c["other"]["amount"]),
                         (2000, 3000, 250, 100))
        m = cur["by_method"]
        self.assertEqual((m["cash"]["amount"], m["upi"]["amount"], m["card"]["amount"], m["bank"]["amount"]), (1250, 4000, 100, 0))
        self.assertEqual(sum(v["amount"] for v in m.values()), cur["total"])

    def test_date_range_filters_payments(self):
        m = self.add(price=0).get_json()
        self.pay(category="other", amount=100, paid_on=day(-40), member_id=m["id"])
        self.pay(category="other", amount=200, paid_on=day(-5))
        self.pay(category="other", amount=400, paid_on=day(0))
        self.assertEqual(self.summary(day(-10), day(0)).get_json()["current"]["total"], 600)
        self.assertEqual(self.summary(day(-60), day(-30)).get_json()["current"]["total"], 100)
        self.assertEqual(self.summary(day(0), day(0)).get_json()["current"]["total"], 400)     # single day, inclusive

    def test_comparison_period_and_series(self):
        self.pay(category="other", amount=100, paid_on=day(-8))
        self.pay(category="other", amount=300, paid_on=day(-1))
        s = self.summary(day(-6), day(0), compare_from=day(-13), compare_to=day(-7)).get_json()
        self.assertEqual(s["current"]["total"], 300)
        self.assertEqual(s["previous"]["total"], 100)
        pts = s["series"]["points"]
        self.assertEqual(s["series"]["granularity"], "day")
        self.assertEqual(len(pts), 7)                                                           # zero-filled, no gaps
        self.assertEqual(sum(p["total"] for p in pts), 300)
        self.assertEqual(pts[-2]["by_category"]["other"], 300)

    def test_long_range_uses_monthly_series(self):
        self.pay(category="other", amount=100, paid_on=day(-100))
        s = self.summary(day(-200), day(0)).get_json()["series"]
        self.assertEqual(s["granularity"], "month")
        self.assertEqual(sum(p["total"] for p in s["points"]), 100)
        keys = [p["key"] for p in s["points"]]
        self.assertEqual(keys, sorted(set(keys)))                                              # unique, ordered months

    def test_joinings_renewals_and_dues(self):
        a, b = self.seed()
        self.c.post(f"/api/members/{a['id']}/renew", json={"plan": "1", "price": 1000, "paid": 0})
        s = self.summary(day(-1), day(40)).get_json()
        self.assertEqual(s["joinings"], 2)
        self.assertEqual(s["renewals"], 1)
        self.assertEqual(s["dues"]["total"], 500 + 1000)
        self.assertEqual(s["dues"]["count"], 2)
        self.assertEqual(s["dues"]["members"][0]["due"], 1000)                                 # biggest first

    def test_transactions_list_filters_search_and_paging(self):
        self.seed()
        r = self.c.get("/api/payments", query_string={"category": "personal_training"}).get_json()
        self.assertEqual((r["count"], r["total"]), (1, 3000))
        self.assertEqual(self.c.get("/api/payments", query_string={"method": "upi"}).get_json()["count"], 2)
        self.assertEqual(self.c.get("/api/payments", query_string={"q": "whey"}).get_json()["count"], 0)
        self.assertEqual(self.c.get("/api/payments", query_string={"q": "walk"}).get_json()["count"], 1)
        self.assertEqual(self.c.get("/api/payments", query_string={"q": "%"}).get_json()["count"], 0)   # LIKE wildcards escaped
        page = self.c.get("/api/payments", query_string={"limit": 2, "offset": 0}).get_json()
        self.assertEqual((len(page["items"]), page["count"]), (2, 5))
        self.assertEqual(self.c.get("/api/payments", query_string={"category": "bogus"}).status_code, 400)

    def test_summary_validation(self):
        self.assertEqual(self.summary("bad", day(0)).status_code, 400)
        self.assertEqual(self.summary(day(0), day(-5)).status_code, 400)
        self.assertEqual(self.summary(day(-4000), day(0)).status_code, 400)

    def test_empty_database_summary_is_all_zeros(self):
        s = self.summary().get_json()
        self.assertEqual(s["current"]["total"], 0)
        self.assertEqual(s["dues"]["count"], 0)


# ─────────────────────────────────────────────────────────────────────
class TestEditAndLegacy(Base):
    def test_edit_member_syncs_latest_period(self):
        m = self.add(price=1000, paid=1000).get_json()
        body = {"name": "Rahul S", "phone": m["phone"], "gender": "male", "plan": "1", "start": m["start"], "expiry": day(45)}
        d = self.c.put(f"/api/members/{m['id']}", json=body).get_json()
        self.assertEqual(d["expiry"], day(45))
        self.assertEqual(d["memberships"][0]["expiry"], day(45))
        self.assertEqual(d["name"], "Rahul S")

    def test_edit_to_a_used_phone_number_is_409(self):
        a = self.add(phone="9000000001").get_json()
        b = self.add(name="B", phone="9000000002").get_json()
        body = {"name": "B", "phone": a["phone"], "gender": "male", "plan": "1", "start": b["start"], "expiry": b["expiry"]}
        r = self.c.put(f"/api/members/{b['id']}", json=body)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.member(b["id"])["phone"], "9000000002")

    def test_edit_cannot_end_before_current_period_starts(self):
        m = self.add(price=0).get_json()
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "price": 0}).get_json()
        body = {"name": m["name"], "phone": m["phone"], "gender": "male", "plan": "1", "start": m["start"], "expiry": m["start"]}
        self.assertEqual(self.c.put(f"/api/members/{m['id']}", json=body).status_code, 400)

    def test_pre_v2_members_get_a_zero_price_period_and_no_fake_dues(self):
        conn = sqlite3.connect(gym.DB_PATH)
        conn.execute("INSERT INTO members VALUES ('m_old','Old Timer','9111111111','male','3',?,?)", (day(-60), day(30)))
        conn.commit()
        conn.close()
        gym.init_db()
        d = self.member("m_old")
        self.assertEqual(len(d["memberships"]), 1)
        self.assertEqual((d["billed"], d["due"], d["paid_total"]), (0, 0, 0))
        self.assertEqual(d["plan_label"], "3 Months")
        gym.init_db()                                                                           # idempotent
        self.assertEqual(len(self.member("m_old")["memberships"]), 1)

    def test_old_endpoints_keep_their_shape(self):
        self.add(name="Soon", phone="9000000001", start=day(-27)).get_json()           # expires in ~3 days
        self.add(name="Later", phone="9000000002", plan="12").get_json()
        members = self.c.get("/api/members").get_json()
        for k in ("id", "name", "phone", "gender", "plan", "start", "expiry"):
            self.assertIn(k, members[0])
        exp = self.c.get("/api/members/expiring/5").get_json()
        self.assertEqual([m["name"] for m in exp], ["Soon"])
        f = self.c.get("/api/members/filter", query_string={"status": "active"}).get_json()
        self.assertEqual([m["name"] for m in f], ["Later"])
        self.assertEqual(len(self.c.get("/api/members/filter", query_string={"gender": "female"}).get_json()), 0)

    def test_bootstrap(self):
        self.add()
        b = self.c.get("/api/bootstrap").get_json()
        self.assertEqual(b["today"], day(0))
        self.assertEqual(len(b["members"]), 1)
        self.assertEqual(b["plan_prices"]["male"]["1"], 1000)
        self.assertFalse(b["revenue_pin_required"])
        self.assertTrue(b["revenue_unlocked"])


# ─────────────────────────────────────────────────────────────────────
class TestSettingsBackupLock(Base):
    def test_plan_prices_update_affects_new_memberships_only(self):
        old = self.add(price=None, phone="9000000001").get_json()
        self.assertEqual(old["memberships"][0]["price"], 1000)
        r = self.c.put("/api/settings/plan-prices", json={"male": {"1": 1200}})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["male"]["1"], 1200)
        self.assertEqual(r.get_json()["male"]["3"], 2500)                                     # untouched
        new = self.add(phone="9000000002").get_json()
        self.assertEqual(new["memberships"][0]["price"], 1200)
        self.assertEqual(self.member(old["id"])["memberships"][0]["price"], 1000)
        self.assertEqual(self.c.put("/api/settings/plan-prices", json={"male": {"2": 100}}).status_code, 400)
        self.assertEqual(self.c.put("/api/settings/plan-prices", json={"male": {"1": 0}}).status_code, 400)
        self.assertEqual(self.c.put("/api/settings/plan-prices", json={}).status_code, 400)

    def test_backup_is_a_valid_sqlite_copy(self):
        self.add(name="Backed Up", price=1000, paid=1000)
        r = self.c.get("/api/backup")
        self.assertEqual(r.status_code, 200)
        path = os.path.join(_TMP, "restored.db")
        with open(path, "wb") as fh:
            fh.write(r.data)
        r.close()                                  # server closes the response → temp file is cleaned up
        conn = sqlite3.connect(path)
        self.assertEqual(conn.execute("SELECT name FROM members").fetchone()[0], "Backed Up")
        self.assertEqual(conn.execute("SELECT SUM(amount) FROM payments").fetchone()[0], 1000)

    def test_revenue_pin_lock(self):
        gym.REVENUE_PIN = "4321"
        m = self.add(price=1000, paid=1000).get_json()
        self.assertFalse(self.c.get("/api/revenue/status").get_json()["unlocked"])
        # gym-wide money is locked...
        for url in ("/api/revenue/summary?from=2026-01-01&to=2026-12-31", "/api/payments", "/api/backup"):
            r = self.c.get(url)
            self.assertEqual((r.status_code, r.get_json().get("code") if r.is_json else None), (403, "revenue_locked"), url)
        pid = m["payments"][0]["id"]
        self.assertEqual(self.c.delete(f"/api/payments/{pid}").status_code, 403)
        self.assertEqual(self.c.put(f"/api/payments/{pid}", json={"amount": 5}).status_code, 403)
        # ...but the front desk can still add members, renew and take payments
        self.assertEqual(self.add(phone="9000000002", price=500, paid=100).status_code, 201)
        self.assertEqual(self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "price": 0}).status_code, 200)
        # wrong PIN, then right PIN
        wrong = self.c.post("/api/revenue/unlock", json={"pin": "0000"})
        self.assertEqual((wrong.status_code, wrong.get_json()["code"]), (403, "bad_pin"))      # 403, never 401 (401 = "logged out")
        self.assertEqual(self.c.get("/api/session").get_json()["authenticated"], True)
        self.assertEqual(self.c.post("/api/revenue/unlock", json={"pin": "4321"}).status_code, 200)
        self.assertEqual(self.c.get("/api/payments").status_code, 200)
        self.assertEqual(self.c.get("/api/revenue/summary", query_string={"from": day(-5), "to": day(0)}).status_code, 200)
        # lock again, and logging out also re-locks
        self.c.post("/api/revenue/lock")
        self.assertEqual(self.c.get("/api/payments").status_code, 403)
        self.c.post("/api/revenue/unlock", json={"pin": "4321"})
        self.c.post("/api/logout")
        self.login()
        self.assertEqual(self.c.get("/api/payments").status_code, 403)

    def test_pin_brute_force_is_throttled(self):
        gym.REVENUE_PIN = "4321"
        for _ in range(gym.FAIL_LIMIT):
            self.c.post("/api/revenue/unlock", json={"pin": "0000"})
        self.assertEqual(self.c.post("/api/revenue/unlock", json={"pin": "4321"}).status_code, 429)

    def test_undo_renewal_with_payments_respects_lock(self):
        m = self.add(price=0).get_json()
        d = self.c.post(f"/api/members/{m['id']}/renew", json={"plan": "1", "price": 1000, "paid": 1000}).get_json()
        gym.REVENUE_PIN = "4321"
        self.assertEqual(self.c.delete(f"/api/memberships/{d['memberships'][0]['id']}").status_code, 403)


# ─────────────────────────────────────────────────────────────────────
class TestMessaging(Base):
    def test_bulk_reminder_refuses_expired_members_and_logs_failures(self):
        gym.META_ACCESS_TOKEN = gym.META_PHONE_NUMBER_ID = None
        expired = self.add(name="Expired", phone="9000000001", start=day(-90)).get_json()
        soon = self.add(name="Soon", phone="9000000002", start=day(-28)).get_json()
        r = self.c.post("/api/reminders/send-bulk", json={"member_ids": [expired["id"], soon["id"], "ghost"]}).get_json()
        self.assertEqual(r["sent"], [])
        reasons = {f["id"]: f["reason"] for f in r["failed"]}
        self.assertIn("expired", reasons[expired["id"]].lower())
        self.assertIn("credentials", reasons[soon["id"]].lower())
        self.assertEqual(reasons["ghost"], "Member not found")
        log = self.c.get("/api/messages/log").get_json()
        self.assertEqual(len(log), 1)                                                          # only the real attempt is logged
        self.assertEqual((log[0]["kind"], log[0]["status"], log[0]["name"]), ("reminder", "failed", "Soon"))

    def test_broadcast_validation(self):
        self.assertEqual(self.c.post("/api/broadcast/send", json={"member_ids": [], "template_name": "gym_announcement"}).status_code, 400)
        m = self.add().get_json()
        self.assertEqual(self.c.post("/api/broadcast/send", json={"member_ids": [m["id"]], "template_name": "nope"}).status_code, 400)
        r = self.c.post("/api/broadcast/send", json={"member_ids": [m["id"]], "template_name": "gym_announcement", "extra_variables": ["hi"]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["failed"]), 1)                                       # no Meta creds in tests

    def test_cron_endpoint_needs_secret(self):
        anon = gym.app.test_client()
        self.assertEqual(anon.post("/api/reminders/check-tomorrow").status_code, 403)
        self.assertEqual(anon.post("/api/reminders/check-tomorrow", headers={"X-CRON-SECRET": "wrong"}).status_code, 403)
        self.assertEqual(anon.post("/api/reminders/check-tomorrow", headers={"X-CRON-SECRET": gym.CRON_SECRET}).status_code, 200)


# ─────────────────────────────────────────────────────────────────────
class TestRestore(Base):
    def _backup_bytes(self):
        r = self.c.get("/api/backup")
        data = r.data
        r.close()
        return data

    def _post(self, data, name="backup.db", dry=False):
        import io
        return self.c.post("/api/restore" + ("?dry_run=1" if dry else ""), data={"file": (io.BytesIO(data), name)},
                           content_type="multipart/form-data")

    def test_roundtrip_dry_run_then_restore(self):
        a = self.add(name="Keep Me", price=1000, paid=1000).get_json()
        snapshot = self._backup_bytes()
        self.add(name="Added Later", phone="9000000002", price=500, paid=500)
        self.pay(category="products", amount=99)
        self.assertEqual(len(self.c.get("/api/members").get_json()), 2)

        dry = self._post(snapshot, dry=True)
        self.assertEqual(dry.status_code, 200, dry.get_json())
        self.assertEqual(dry.get_json()["counts"], {"members": 1, "memberships": 1, "payments": 1})
        self.assertEqual(len(self.c.get("/api/members").get_json()), 2)           # dry run changed nothing

        r = self._post(snapshot)
        self.assertEqual(r.status_code, 200, r.get_json())
        names = [m["name"] for m in self.c.get("/api/members").get_json()]
        self.assertEqual(names, ["Keep Me"])
        self.assertEqual(self.c.get("/api/payments").get_json()["total"], 1000)    # the later ₹99 sale is gone too
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(gym.DB_PATH), "pre-restore-backup.db")))
        self.assertEqual(self.member(a["id"])["due"], 0)

    def test_rejects_junk_files(self):
        self.assertEqual(self._post(b"this is not a database").status_code, 400)
        self.assertEqual(self.c.post("/api/restore").status_code, 400)             # no file at all
        other = os.path.join(_TMP, "other.db")
        conn = sqlite3.connect(other)
        conn.execute("CREATE TABLE foo (x INTEGER)")
        conn.commit()
        conn.close()
        r = self._post(_read(other))
        self.assertEqual(r.status_code, 400)
        self.assertIn("isn't an X GYM backup", r.get_json()["error"])
        self.add(name="Still Here")
        self.assertEqual(len(self.c.get("/api/members").get_json()), 1)            # bad uploads never touch live data

    def test_old_pre_v2_backup_is_upgraded_on_restore(self):
        old = os.path.join(_TMP, "old_v1.db")
        if os.path.exists(old):
            os.unlink(old)
        conn = sqlite3.connect(old)
        conn.execute("""CREATE TABLE members (id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE,
                        gender TEXT NOT NULL, plan TEXT NOT NULL, start DATE NOT NULL, expiry DATE NOT NULL)""")
        conn.execute("INSERT INTO members VALUES ('m_old','Old Timer','9111111111','male','3',?,?)", (day(-60), day(30)))
        conn.commit()
        conn.close()
        r = self._post(_read(old))
        self.assertEqual(r.status_code, 200, r.get_json())
        d = self.member("m_old")
        self.assertEqual((len(d["memberships"]), d["due"]), (1, 0))               # migrated, no fake dues
        self.assertEqual(self.c.get("/api/bootstrap").get_json()["plan_prices"]["male"]["1"], 1000)

    def test_restore_needs_login_and_respects_revenue_lock(self):
        snap = self._backup_bytes()
        anon = gym.app.test_client()
        import io
        self.assertEqual(anon.post("/api/restore", data={"file": (io.BytesIO(snap), "b.db")}, content_type="multipart/form-data").status_code, 401)
        gym.REVENUE_PIN = "4321"
        self.assertEqual(self._post(snap).status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
