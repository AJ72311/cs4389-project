"""
Leaked secret key test and timing for the insecure deserialization module (Shreya Balaji).

    python demo_deserialization_keyleak.py

Part 1: In vulnerable mode, /debug/config (misconfig.py) leaks the app's secret key.
The secure cart cookie is signed with that key, so an attacker who has the key can
make cookies with a valid signature. This checks which attacks the other defenses
(allowlist check, prices from the database, buyer from the session) still stop.

Part 2: With a strong random key (what APP_MODE=hardened sets at startup), a cookie
signed with the leaked key is rejected.

Part 3: Timing of the vulnerable and secure cart loading and checkout.
"""

import os
import time

from itsdangerous import URLSafeSerializer

import deserialization
import misconfig
from app import app

LAPTOP_ID = 1


def login(client):
    client.post("/login", data={"username": "alice", "password": "password123"})


def try_forged(client, key, payload):
    forged = URLSafeSerializer(key, salt="cart-v1").dumps(payload)
    client.set_cookie(deserialization.SECURE_COOKIE, forged)
    return client.post("/api/secure/checkout")


def leaked_key_demo():
    print("\nPART 1: attacker has the leaked secret key")
    original = misconfig.VULNERABLE
    misconfig.VULNERABLE = True
    client = app.test_client()
    key = client.get("/debug/config").get_json()["secret_key"]
    misconfig.VULNERABLE = original
    print(f"Key from /debug/config: {key!r}")

    login(client)
    attacks = [
        ("Extra price field", {"items": [{"id": LAPTOP_ID, "qty": 1}], "price": 0.01}),
        ("Price inside item", {"items": [{"id": LAPTOP_ID, "qty": 1, "price": 0.01}]}),
        ("Buyer set to admin", {"user": "admin", "items": [{"id": LAPTOP_ID, "qty": 1}]}),
        ("Quantity of 500", {"items": [{"id": LAPTOP_ID, "qty": 500}]}),
        ("Product that doesn't exist", {"items": [{"id": 9999, "qty": 1}]}),
    ]
    results = {}
    for name, payload in attacks:
        r = try_forged(client, key, payload)
        results[name] = r.status_code
        print(f"  {name:<28} -> {r.status_code} {r.get_json()}")

    r = try_forged(client, key, {"items": [{"id": LAPTOP_ID, "qty": 1}]})
    body = r.get_json()
    results["valid_shape"] = body
    print(f"  {'Correctly shaped cart':<28} -> {r.status_code} {body}")
    return results


def strong_key_demo():
    print("\nPART 2: app uses a strong random key (APP_MODE=hardened)")
    original_key, original_mode = app.secret_key, misconfig.VULNERABLE
    app.secret_key = os.urandom(32)
    misconfig.VULNERABLE = False
    try:
        client = app.test_client()
        debug = client.get("/debug/config").status_code
        login(client)
        r = try_forged(client, "key-123", {"items": [{"id": LAPTOP_ID, "qty": 1}]})
        print(f"  /debug/config                -> {debug}")
        print(f"  Cookie signed with key-123   -> {r.status_code} {r.get_json()}")
        return debug, r.status_code
    finally:
        app.secret_key, misconfig.VULNERABLE = original_key, original_mode


def timing(runs=200):
    print(f"\nPART 3: timing ({runs} runs each)")
    results = {}
    for version, cookie in (("vulnerable", deserialization.VULN_COOKIE),
                            ("secure", deserialization.SECURE_COOKIE)):
        client = app.test_client()
        login(client)
        client.post(f"/api/{version}/cart/add", json={"product_id": LAPTOP_ID, "qty": 1})
        raw = client.get_cookie(cookie).value
        load = deserialization._vuln_load if version == "vulnerable" else deserialization._secure_load
        with app.app_context():
            start = time.perf_counter()
            for _ in range(runs * 50):
                load(raw)
            load_us = (time.perf_counter() - start) / (runs * 50) * 1e6

        start = time.perf_counter()
        for _ in range(runs):
            client.set_cookie(cookie, raw)
            client.post(f"/api/{version}/checkout")
        checkout_ms = (time.perf_counter() - start) / runs * 1000
        results[version] = (load_us, checkout_ms)
        print(f"  {version:<10} load cookie: {load_us:6.1f} microseconds   full checkout: {checkout_ms:5.2f} ms")
    return results


if __name__ == "__main__":
    leak = leaked_key_demo()
    debug_status, strong = strong_key_demo()
    times = timing()

    blocked = [n for n, s in leak.items() if n != "valid_shape" and s == 400]
    print("\nSUMMARY")
    print(f"Leaked key: {len(blocked)} of 5 tampering attempts still rejected with HTTP 400")
    print(f"Leaked key: a correctly shaped cart was charged ${leak['valid_shape']['total']} "
          f"to '{leak['valid_shape']['charged_user']}' (price and buyer can't be changed)")
    print(f"Strong key: /debug/config -> {debug_status}, cookie signed with key-123 -> {strong}")
    extra = times["secure"][1] - times["vulnerable"][1]
    print(f"Secure checkout took {extra:+.2f} ms compared with the vulnerable one")

    assert len(blocked) == 5
    assert leak["valid_shape"]["total"] == 999.99 and leak["valid_shape"]["charged_user"] == "alice"
    assert debug_status == 404 and strong == 400
    print("\nAll checks passed.")
