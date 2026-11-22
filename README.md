# Defending the Web: Empirical Exploitation and Remediation of OWASP Top 10 Vulnerabilities
**CS4389 Data and Applications Security**

**Group members:** AJ Yaseen, Hamza Ghaffari, Nitin Thota, Prajit Alexander, Michael Han, Marc Gerald Sahagun, Shreya Balaji, Sreyas Chakka, Jerry Chen

---

## Dependencies
* Python 3.9 or newer
* Packages listed in `requirements.txt` (Flask, Werkzeug, Jinja2)
* SQLite (included with Python, the database file `shop.db` is automatically created if it doesn't already exist)

---

## Installation
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
On Windows, activate with `venv\Scripts\activate` instead

---

## Execution
`python app.py` or `python3 app.py`, then open http://localhost:8000 in your browser.

---

## Test Credentials
* `admin` / `admin123`
* `alice` / `password123`

---

## Using the Demos
The home page has a demo button for each vulnerability, open one and follow the steps on its page

The bar at the top displays the current mode, vulnerable or hardened, and the app will always start in vulnerable mode by default. After you log in, press the "Switch" button to change it.

---

## Test Scripts
`python verify_all.py` checks all seven vulnerabilities and prints a PASS or FAIL table

Each vulnerability also has its own script: `demo_sqli.py`, `demo_xss.py`, `demo_idor.py`, `demo_csrf.py` and `demo_deserialization.py`

The scripts add test data to the database, so between each run, stop the app in your terminal, delete the database with "rm shop.db" (macOS or Linux) or "del shop.db" (Windows), and start the app again

---

## Vulnerable Dependencies Check
Install the scanner inside your venv with `pip install pip-audit`. The scans need an internet connection.

* `python audit_dependencies.py` scans both package lists and prints PASS or FAIL
* `python audit_dependencies.py --mode vulnerable` scans one list (exit code 0 clean, 1 findings, 2 error)
* `python audit_dependencies.py --save` also rewrites `audit-vuln.txt` and `audit-patched.txt`
* `python audit_dependencies.py --switch vulnerable` or `--switch patched` installs that set into the venv. Restart the app afterward. It refuses to run outside a venv unless you add `--force`

`verify_all.py` uses the same live scan and falls back to the saved audit files if pip-audit or the network is unavailable.

---

## Project Files
* `app.py`, `database.py`, `walkthrough.py`, `templates/`, `static/`: the shop, the demo pages and the Switch button (AJ Yaseen)
* `sqli.py`: SQL injection (Hamza Ghaffari)
* `xss.py`: cross-site scripting (Nitin Thota)
* `idor.py`: broken access control (Prajit Alexander)
* `csrf.py`: cross-site request forgery (Michael Han)
* `misconfig.py`: security misconfiguration (Marc Gerald Sahagun)
* `deserialization.py`: insecure deserialization (Shreya Balaji)
* `requirements-vuln.txt`, `requirements.txt`, `audit_dependencies.py`, `audit-vuln.txt`, `audit-patched.txt`: vulnerable dependencies (Sreyas Chakka)

---

## Limitations
* The "Add to Cart" buttons on the home page are placeholders, the cart is demonstrated on the insecure deserialization page.
* Library versions are set during installation, so the vulnerable dependencies page has no Switch button. Use `python audit_dependencies.py --switch` and restart the app instead.
* The dependency scan only finds published advisories, needs internet access, and may miss transitive vulnerabilities. Its results change as the advisory database is updated.
