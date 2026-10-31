"""
Demo for the cross-site request forgery module.

Scenario: alice is logged in to the shop and visits an attacker's page that
silently POSTs a store credit transfer to the attacker's account. The forged
request carries her session cookie but not the CSRF token, because the
attacker's page can't read it. On the vulnerable route her money is sent; on
the secure route it's rejected with 403. A real transfer from the shop's own
form (with the token) still works.

To run this program, type in python demo_csrf.py. 
By: Michael Han
"""

from app import app
from csrf import ATTACKER_AMOUNT, ATTACKER_USER, STARTING_BALANCE, get_balance, set_balance

FORGED = {"recipient": ATTACKER_USER, "amount": str(ATTACKER_AMOUNT)}

def banner(text):
    print("\n" + "=" * 70 + "\n" + text + "\n" + "=" * 70)

#login as a user with the given username and password.
def login(client, username, password):
    client.post("/login", data={"username": username, "password": password})

#get the token of the client 
def get_token(client):
    with client.session_transaction() as s:
        return s.get("csrf_token")

#reset the balances
def reset(version):
    # Start each run from the same balances so the numbers are repeatable.
    set_balance("alice", version, STARTING_BALANCE)
    set_balance("admin", version, STARTING_BALANCE)
    set_balance(ATTACKER_USER, version, 0)

#the vulnerable program: no CSRF protection
def vulnerable_demo():
    banner("VULNERABLE: no CSRF token")
    reset("vulnerable")
    c = app.test_client()
    login(c, "alice", "password123")
    print("Alice's balance: ", get_balance("alice", "vulnerable"))

    # Forged request: same cookie, only the fields the attacker's form has.
    r = c.post("/csrf/vulnerable/wallet", data=FORGED)
    print("Forged POST status: ", r.status_code)
    print("Alice's balance after attack: ", get_balance("alice", "vulnerable"))
    print("Attacker's balance: ", get_balance(ATTACKER_USER, "vulnerable"))

    return {"stolen": get_balance(ATTACKER_USER, "vulnerable") == ATTACKER_AMOUNT}

#the secure program: synchronizer token pattern
def secure_demo():
    banner("SECURE: synchronizer CSRF token")
    reset("secure")
    c = app.test_client()
    login(c, "alice", "password123")

    c.get("/csrf/secure/wallet")  # loading the page issues the token
    token = get_token(c)
    r = c.post("/csrf/secure/wallet",
               data={"recipient": "admin", "amount": "25", "csrf_token": token})
    legit_ok = r.status_code == 302 and get_balance("admin", "secure") == STARTING_BALANCE + 25
    print("Alice sends $25 to admin (with token), status:", r.status_code)
    print("Alice's balance: ", get_balance("alice", "secure"))

    r_missing = c.post("/csrf/secure/wallet", data=FORGED)
    print("Forged POST, no token, status: ", r_missing.status_code)

    r_wrong = c.post("/csrf/secure/wallet", data={**FORGED, "csrf_token": "guessed-token"})
    print("Forged POST, wrong token, status: ", r_wrong.status_code)
    print("Alice's balance after attacks: ", get_balance("alice", "secure"))
    print("Attacker's balance: ", get_balance(ATTACKER_USER, "secure"))

    return {
        "legit_ok": legit_ok,
        "blocked": r_missing.status_code == 403 and r_wrong.status_code == 403,
        "unchanged": get_balance(ATTACKER_USER, "secure") == 0,
    }

# main execution
if __name__ == "__main__":
    r1 = vulnerable_demo() #the vulnerable program: no CSRF protection
    r2 = secure_demo() #the secure program: synchronizer token pattern
