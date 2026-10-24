# Defending the Web: Empirical Exploitation and Remediation of OWASP Top 10 Vulnerabilities
**CS4389 Data and Applications Security**

**Group members:** AJ Yaseen, Hamza Ghaffari, Nitin Thota, Prajit Alexander, Michael Han, Marc Gerald Sahagun, Shreya Balaji, Sreyas Chakka, Jerry Chen

---

## Dependencies
* Python 3+
* Flask

---

## Installation
`pip install flask`

---

## Execution
`python app.py` or `python3 app.py`

---

## Test Credentials
* `admin` / `admin123`
* `alice` / `password123`

---

## Current Status (Deliverable 1)

### What currently works:
SQLite schema generation, product catalog display, user session authentication, session termination, access control setup, basic vulnerability implementations.

To execute the cross-site scripting demonstration, launch the core server via `python app.py`. Authenticate using the alice test credentials, then evaluate the endpoint pairs: `/xss/vulnerable/search` against `/xss/secure/search` for reflected vectors, and `/xss/vulnerable/reviews` against `/xss/secure/reviews` for stored vectors. To execute automated test scripts and output verification metrics, execute `python demo_xss.py`.

### What does not work yet:
* Attack demonstration scripts and defensive patches for SQL Injection and CSRF, plus thorough validation across all modules.
* Production server setup for hardened mode, default admin credentials still in the seed data, and session cookie flags. 

### What we plan to add:
A consistent vulnerable versus hardened toggle across all modules, since only the misconfiguration module has one so far.