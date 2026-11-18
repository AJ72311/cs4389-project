"""
Cross-site request forgery (CSRF) module (OWASP A01: Broken Access Control).

2 scenarios are shown in the code: one without a CSRF token and one with a CSRF token. 
Scenario: The attacker wants to steal money from the user during transfer:

    The vulnerable code trusts any POST that arrives with a valid session
    cookie, so a page on another site can auto-submit a hidden form and
    the victim's browser attaches the cookie for it. 
    The secure route also requires a random per-session token that is only ever placed
    inside our own page, which the attacker's page cannot read, so the
    forged transfer is rejected.

    Attacker page (/csrf/attacker?target=vulnerable|secure)
    Simulates the evil site. Open it at http://127.0.0.1:5000 while
    logged in at http://localhost:5000 so the browser treats it as a
    different site.

    Do NOT run the program here. Run it on demo_csrf.py 
    By: Michael Han
"""
#imports
import hmac
import secrets
#essential libraries
from flask import Blueprint, abort, redirect, render_template, request, session, url_for
#database
from database import get_db

csrf_bp = Blueprint('csrf', __name__)
#variables (used for testing)
STARTING_BALANCE = 100.00
ATTACKER_USER = 'attacker'
ATTACKER_AMOUNT = 100.00

#create a table to store the balances of each user.
def init_wallets_table():
    conn = get_db()
    conn.execute(
        'CREATE TABLE IF NOT EXISTS wallets ('
        'username TEXT, version TEXT, balance REAL, '
        'PRIMARY KEY (username, version))'
    )
    conn.commit()
    conn.close()

#accessor method to get the balance of user
def get_balance(username, version):
    # Every account starts with some store credit the first time it's looked up.
    conn = get_db()
    conn.execute(
        'INSERT OR IGNORE INTO wallets (username, version, balance) VALUES (?, ?, ?)',
        (username, version, STARTING_BALANCE),
    )
    conn.commit()
    row = conn.execute(
        'SELECT balance FROM wallets WHERE username = ? AND version = ?',
        (username, version),
    ).fetchone()
    conn.close()
    return row['balance']

#mutator method that sets the balance of user (updates during money transfer)
def set_balance(username, version, balance):
    conn = get_db()
    conn.execute(
        'INSERT OR REPLACE INTO wallets (username, version, balance) VALUES (?, ?, ?)',
        (username, version, balance),
    )
    conn.commit()
    conn.close()

#transfer money from one user to another. 
def transfer(sender, recipient, amount, version):
    # Both routes validate the transfer the same way.
    if not recipient or recipient == sender:
        return 'Pick a different recipient'
    if not amount > 0:
        #no negative money 
        return 'Amount must be positive'
    if amount > get_balance(sender, version):
        return 'Insufficient funds'
    get_balance(recipient, version)  # make sure the recipient has a wallet to store the transfered money

    conn = get_db()
    conn.execute(
        'UPDATE wallets SET balance = round(balance - ?, 2) WHERE username = ? AND version = ?',
        (amount, sender, version),
    )
    conn.execute(
        'UPDATE wallets SET balance = round(balance + ?, 2) WHERE username = ? AND version = ?',
        (amount, recipient, version),
    )
    conn.commit()
    conn.close()
    return None

# Form used to order the transfer request 
def parse_transfer_form():
    recipient = request.form.get('recipient', '').strip()
    try:
        amount = round(float(request.form.get('amount', '')), 2)
    except ValueError:
        abort(400, description='Amount must be a number')
    return recipient, amount


# CSRF token helpers
def get_csrf_token():
    # One unguessable token per session, generated on first use.
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

# Checks to see if the CSRF token is valid.
def csrf_token_valid():
    expected = session.get('csrf_token')
    submitted = request.form.get('csrf_token', '')
    # Constant-time compare so the token can't be guessed byte by byte.
    return bool(expected) and hmac.compare_digest(expected, submitted)

#VULNERABLE program: no CSRF protection
@csrf_bp.route('/csrf/vulnerable/wallet', methods=['GET', 'POST'])
def wallet_vulnerable():
    if 'user' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        # VULNERABLE: the session cookie is the only check, and the browser
        # sends it automatically even when the form came from another site.
        recipient, amount = parse_transfer_form()
        error = transfer(session['user'], recipient, amount, 'vulnerable')
        if not error:
            return redirect(url_for('csrf.wallet_vulnerable'))

    return render_template(
        'csrf_wallet.html', safe=False, user=session['user'], error=error,
        balance=get_balance(session['user'], 'vulnerable'),
        action=url_for('csrf.wallet_vulnerable'),
    )

#SECURE program: synchronizer token pattern
@csrf_bp.route('/csrf/secure/wallet', methods=['GET', 'POST'])
def wallet_secure():
    if 'user' not in session:
        return redirect(url_for('login'))

    error = None
    if request.method == 'POST':
        # Mitigation: the request checks the CSRF token. Attacker does not know it
        if not csrf_token_valid():
            abort(403, description='CSRF token missing or invalid')
        recipient, amount = parse_transfer_form()
        error = transfer(session['user'], recipient, amount, 'secure')
        if not error:
            return redirect(url_for('csrf.wallet_secure'))

    return render_template(
        'csrf_wallet.html', safe=True, user=session['user'], error=error,
        balance=get_balance(session['user'], 'secure'),
        action=url_for('csrf.wallet_secure'),
        csrf_token=get_csrf_token(),
    )

#ATTACKER PAGE (simulated evil website)
@csrf_bp.route('/csrf/attacker')
def attacker():
    target = request.args.get('target', 'vulnerable')
    if target not in ('vulnerable', 'secure'):
        abort(400)
    # Absolute URL on localhost so the page can be loaded from 127.0.0.1.
    action = 'http://localhost:5000' + url_for('csrf.wallet_' + target)
    return render_template(
        'csrf_attacker.html', action=action,
        recipient=ATTACKER_USER, amount=ATTACKER_AMOUNT,
    )
