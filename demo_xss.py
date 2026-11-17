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


def defenses_demo():
    banner("DEFENSE IN DEPTH: CSP, HttpOnly cookie, JS-context encoding")
    c = app.test_client()

    # 1. CSP header on the secure pages only.
    secure_csp = c.get("/xss/secure/search").headers.get("Content-Security-Policy", "")
    vuln_csp = c.get("/xss/vulnerable/search").headers.get("Content-Security-Policy", "")
    csp_ok = "script-src 'self'" in secure_csp and "unsafe-inline" not in secure_csp
    print("1. Secure page sends a CSP that blocks inline scripts:", csp_ok)
    print("   Vulnerable page CSP:", vuln_csp or "(none)")

    # 2. HttpOnly + SameSite on the session cookie set at login.
    r = c.post("/login", data={"username": "alice", "password": "password123"})
    cookie = r.headers.get("Set-Cookie", "")
    httponly_ok = "HttpOnly" in cookie
    print("2. Session cookie is HttpOnly:", httponly_ok, "| SameSite=Lax:", "SameSite=Lax" in cookie)

    # 3. The search term handed to JavaScript is JSON-encoded, not raw.
    body = c.get("/xss/secure/search", query_string={"q": PAYLOAD}).data.decode()
    start = body.index('id="search-data">') + len('id="search-data">')
    block = body[start:body.index("</script>", start)]
    js_ok = "\\u003cscript\\u003e" in block and "<script>" not in block
    print("3. Search term in the JS data block is encoded:", js_ok, "->", block)

    return {"csp": csp_ok, "httponly": httponly_ok, "js": js_ok}


if __name__ == "__main__":
    r1 = reflected_demo()
    r2 = stored_demo()
    r3 = defenses_demo()

    banner("SUMMARY")
    print(f"Reflected: vulnerable ran the payload -> {r1['vuln_raw']}, "
          f"secure escaped it -> {r1['secure_escaped']} (raw present: {r1['secure_raw']})")
    print(f"Stored:    vulnerable ran the payload -> {r2['vuln_raw']}, "
          f"secure escaped it -> {r2['secure_escaped']} (raw present: {r2['secure_raw']})")

    assert r1["vuln_raw"] and not r1["secure_raw"] and r1["secure_escaped"]
    print(f"Defenses:  CSP -> {r3['csp']}, HttpOnly -> {r3['httponly']}, "
          f"JS-context encoding -> {r3['js']}")

    assert r2["vuln_raw"] and not r2["secure_raw"] and r2["secure_escaped"]
    assert r3["csp"] and r3["httponly"] and r3["js"]
    print("\nAll checks passed.")