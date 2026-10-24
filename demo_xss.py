"""
Demo for the cross-site scripting module (Nitin Thota).

Runs both versions in-process with Flask's test client, so no server is needed:

    python demo_xss.py

Scenario: a visitor searches the shop and a customer posts a review, both
containing a <script> tag. On the vulnerable routes it would run in anyone
else's browser (cookie theft, page defacement); on the secure routes it just
shows up as text.
"""

from app import app

PAYLOAD = "<script>alert('xss')</script>"


def banner(text):
    print("\n" + "=" * 70 + "\n" + text + "\n" + "=" * 70)


def login(client, username, password):
    client.post("/login", data={"username": username, "password": password})


def reflected_demo():
    banner("REFLECTED XSS: product search")
    c = app.test_client()

    r = c.get("/xss/vulnerable/search", query_string={"q": PAYLOAD})
    vuln_body = r.data.decode()
    print("1. Vulnerable page, raw payload present:", PAYLOAD in vuln_body)

    r = c.get("/xss/secure/search", query_string={"q": PAYLOAD})
    secure_body = r.data.decode()
    print("2. Secure page,    raw payload present:", PAYLOAD in secure_body)
    print("   Secure page,    escaped form present:", "&lt;script&gt;" in secure_body)

    return {
        "vuln_raw": PAYLOAD in vuln_body,
        "secure_raw": PAYLOAD in secure_body,
        "secure_escaped": "&lt;script&gt;" in secure_body,
    }


def stored_demo():
    banner("STORED XSS: product reviews")
    c = app.test_client()
    login(c, "alice", "password123")

    c.post("/xss/vulnerable/reviews", data={"body": PAYLOAD})
    r = c.get("/xss/vulnerable/reviews")
    vuln_body = r.data.decode()
    print("1. Vulnerable reviews page, raw payload present:", PAYLOAD in vuln_body)

    c.post("/xss/secure/reviews", data={"body": PAYLOAD})
    r = c.get("/xss/secure/reviews")
    secure_body = r.data.decode()
    print("2. Secure reviews page,    raw payload present:", PAYLOAD in secure_body)
    print("   Secure reviews page,    escaped form present:", "&lt;script&gt;" in secure_body)

    return {
        "vuln_raw": PAYLOAD in vuln_body,
        "secure_raw": PAYLOAD in secure_body,
        "secure_escaped": "&lt;script&gt;" in secure_body,
    }


if __name__ == "__main__":
    r1 = reflected_demo()
    r2 = stored_demo()

    banner("SUMMARY")
    print(f"Reflected: vulnerable ran the payload -> {r1['vuln_raw']}, "
          f"secure escaped it -> {r1['secure_escaped']} (raw present: {r1['secure_raw']})")
    print(f"Stored:    vulnerable ran the payload -> {r2['vuln_raw']}, "
          f"secure escaped it -> {r2['secure_escaped']} (raw present: {r2['secure_raw']})")

    assert r1["vuln_raw"] and not r1["secure_raw"] and r1["secure_escaped"]
    assert r2["vuln_raw"] and not r2["secure_raw"] and r2["secure_escaped"]
    print("\nAll checks passed.")