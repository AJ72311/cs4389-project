"""
Demo for the insecure deserialization module (Shreya Balaji).

Runs both versions in-process with Flask's test client, so no server is needed:

    python demo_deserialization.py

Scenario: alice (a customer) buys a $999.99 laptop. She edits her cart cookie
so the price is $0.01 and the buyer is "admin", then checks out.
"""

import base64
import json

from app import app

LAPTOP_ID = 1


def banner(text):
    print("\n" + "=" * 70 + "\n" + text + "\n" + "=" * 70)


def login(client, username, password):
    client.post("/login", data={"username": username, "password": password})


def vulnerable_demo():
    banner("VULNERABLE: unsigned base64 JSON cart cookie")
    c = app.test_client()
    login(c, "alice", "password123")

    c.post("/api/vulnerable/cart/add", json={"product_id": LAPTOP_ID, "qty": 1})
    raw = c.get_cookie("cart_v").value
    cart = json.loads(base64.b64decode(raw))
    print("1. Cookie as issued (decoded):", json.dumps(cart))

    cart["items"][0]["price"] = 0.01
    cart["user"] = "admin"
    forged = base64.b64encode(json.dumps(cart).encode()).decode()
    c.set_cookie("cart_v", forged)
    print("2. Attacker edits cookie:     ", json.dumps(cart))

    r = c.post("/api/vulnerable/checkout")
    print("3. Checkout response:", r.status_code, r.get_json())
    return r.get_json()


def secure_demo():
    banner("SECURE: signed, minimal, allowlist-validated cart cookie")
    c = app.test_client()
    login(c, "alice", "password123")

    r = c.post("/api/secure/cart/add", json={"product_id": LAPTOP_ID, "qty": 1})
    raw = c.get_cookie("cart_s").value
    payload = raw.split(".")[0]
    decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    print("1. Cookie as issued:", raw)
    print("   Payload holds only IDs/qty:", decoded.decode())

    results = {}

    # Attack A: change the payload, keep the old signature.
    tampered = json.dumps({"items": [{"id": LAPTOP_ID, "qty": 1}], "price": 0.01}).encode()
    forged = base64.urlsafe_b64encode(tampered).decode().rstrip("=") + "." + raw.split(".")[1]
    c.set_cookie("cart_s", forged)
    r = c.post("/api/secure/checkout")
    print("2. Tampered payload, old signature ->", r.status_code, r.get_json())
    results["tampered"] = r.status_code

    # Attack B: drop the signature entirely (the vulnerable app's format).
    c.set_cookie("cart_s", base64.b64encode(b'{"items":[{"id":1,"qty":1}]}').decode())
    r = c.post("/api/secure/checkout")
    print("3. Unsigned cookie                ->", r.status_code, r.get_json())
    results["unsigned"] = r.status_code

    # Legitimate checkout: price from DB, buyer from session.
    c.post("/api/secure/cart/add", json={"product_id": LAPTOP_ID, "qty": 1})
    r = c.post("/api/secure/checkout")
    print("4. Legitimate checkout            ->", r.status_code, r.get_json())
    results["legit"] = r.get_json()

    # Input validation on the add route itself.
    r = c.post("/api/secure/cart/add", json={"product_id": LAPTOP_ID, "qty": -5})
    print("5. Negative quantity on add       ->", r.status_code, r.get_json())
    results["negative_qty"] = r.status_code
    return results


if __name__ == "__main__":
    v = vulnerable_demo()
    s = secure_demo()

    banner("SUMMARY")
    print(f"Vulnerable: laptop bought for ${v['total']} and billed to '{v['charged_user']}'")
    print(f"Secure: tampered cookie -> HTTP {s['tampered']}, unsigned cookie -> HTTP {s['unsigned']}, "
          f"negative qty -> HTTP {s['negative_qty']}")
    print(f"Secure: legitimate order charged ${s['legit']['total']} to '{s['legit']['charged_user']}'")

    assert v["total"] == 0.01 and v["charged_user"] == "admin"
    assert s["tampered"] == 400 and s["unsigned"] == 400 and s["negative_qty"] == 400
    assert s["legit"]["total"] == 999.99 and s["legit"]["charged_user"] == "alice"
    print("\nAll checks passed.")
