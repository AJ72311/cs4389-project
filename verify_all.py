import contextlib
import io

from app import app
import audit_dependencies
import demo_csrf
import demo_deserialization
import demo_idor
import demo_sqli
import demo_xss
import misconfig


def quiet(function, *args):
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args)


def check_sqli():
    return demo_sqli.verdict(quiet(demo_sqli.run, "vulnerable"), quiet(demo_sqli.run, "secure"))


def check_xss():
    reflected = quiet(demo_xss.reflected_demo)
    stored = quiet(demo_xss.stored_demo)
    works = reflected["vuln_raw"] and stored["vuln_raw"]
    blocked = (not reflected["secure_raw"] and reflected["secure_escaped"]
               and not stored["secure_raw"] and stored["secure_escaped"])
    return works, blocked


def check_idor():
    return demo_idor.verdict(quiet(demo_idor.vulnerable_demo), quiet(demo_idor.secure_demo))


def check_csrf():
    v = quiet(demo_csrf.vulnerable_demo)
    s = quiet(demo_csrf.secure_demo)
    return v["stolen"], s["blocked"] and s["unchanged"] and s["legit_ok"]


def check_deserialization():
    v = quiet(demo_deserialization.vulnerable_demo)
    s = quiet(demo_deserialization.secure_demo)
    works = v["total"] == 0.01 and v["charged_user"] == "admin"
    blocked = (s["tampered"] == 400 and s["unsigned"] == 400 and s["negative_qty"] == 400
               and s["legit"]["total"] == 999.99)
    return works, blocked


def check_misconfig():
    c = app.test_client()
    original = misconfig.VULNERABLE
    misconfig.VULNERABLE = True
    leak = c.get("/debug/config")
    open_headers = c.get("/").headers
    misconfig.VULNERABLE = False
    gone = c.get("/debug/config")
    closed_headers = c.get("/").headers
    misconfig.VULNERABLE = original
    works = leak.status_code == 200 and "secret_key" in leak.get_json() and "X-Powered-By" in open_headers
    blocked = gone.status_code == 404 and "Content-Security-Policy" in closed_headers and "X-Powered-By" not in closed_headers
    return works, blocked


def check_dependencies():
    # Live scan with pip-audit (Sreyas Chakka). Falls back to the saved results
    # if pip-audit or the network is unavailable.
    vulnerable = audit_dependencies.run_audit("vulnerable")
    patched = audit_dependencies.run_audit("patched")
    if vulnerable["status"] != "error" and patched["status"] != "error":
        return vulnerable["status"] == "findings", patched["status"] == "clean"

    print("Dependencies: live scan unavailable, using saved audit files.")
    with open("audit-vuln.txt") as f:
        saved_vulnerable = f.read()
    with open("audit-patched.txt") as f:
        saved_patched = f.read()
    return "PYSEC" in saved_vulnerable, "No known vulnerabilities found" in saved_patched


CHECKS = [
    ("SQL injection", check_sqli),
    ("Cross-site scripting", check_xss),
    ("Broken access control", check_idor),
    ("Cross-site request forgery", check_csrf),
    ("Insecure deserialization", check_deserialization),
    ("Security misconfiguration", check_misconfig),
    ("Vulnerable dependencies", check_dependencies),
]


if __name__ == "__main__":
    print(f"{'Vulnerability':<30}{'Attack works':<16}{'Hardened blocks it':<22}{'Result'}")
    failures = 0
    for name, check in CHECKS:
        works, blocked = check()
        passed = bool(works and blocked)
        failures += not passed
        print(f"{name:<30}{str(bool(works)):<16}{str(bool(blocked)):<22}{'PASS' if passed else 'FAIL'}")

    assert failures == 0
    print("\nAll checks passed.")
