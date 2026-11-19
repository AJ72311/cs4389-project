"""
Cross-site scripting (XSS) module (OWASP A03: Injection -> XSS).
Owner: Nitin Thota

Two pairs of routes show the same feature done unsafely and safely:

  Reflected  (/xss/vulnerable/search, /xss/secure/search)
      A product search box. The vulnerable route puts the search term
      straight into the page. The secure route renders it through
      Jinja's normal auto-escaping, so the same input just shows up as
      text instead of running.

  Stored     (/xss/vulnerable/reviews, /xss/secure/reviews)
      A product review box. The vulnerable route saves and shows review
      text as-is (marked |safe), so anyone's browser that loads the
      reviews page runs it. The secure route trims/limits the input and
      escapes it on output, so a script in a review just shows up as
      text to every visitor instead of running.

Defense in depth on the secure routes (on top of output escaping):

  1. Content-Security-Policy header: the browser refuses inline scripts
     and scripts from other sites, so even if escaping were missed
     somewhere, an injected <script> would not run.
  2. HttpOnly session cookie: in hardened mode page scripts cannot read the
     session cookie, so a stolen-cookie payload gets nothing (see the
     cookie-theft demo in demo_xss.py). Set in harden_session_cookie().
  3. JavaScript-context encoding: when user input is handed to JavaScript,
     it goes through Jinja's |tojson filter (which escapes <, >, & and
     quotes) inside a non-executing JSON data block, and the static script
     writes it to the page with textContent, never innerHTML.

Cookie theft in the browser: in vulnerable mode, post the steal payload
from demo_xss.py as a review on /xss/vulnerable/reviews, then open
/xss/attacker/log (stolen cookies are also printed in the server terminal).
In hardened mode the app-wide CSP from misconfig.py also covers the
vulnerable pages, so the injected script is blocked before it runs; the
HttpOnly check on its own is shown by demo_xss.py.
"""

from flask import Blueprint, jsonify, make_response, redirect, render_template, request, session, url_for

from database import get_db
import misconfig  # APP_MODE drives the session cookie's HttpOnly and SameSite flags

xss_bp = Blueprint('xss', __name__)

# Simulated attacker collector. In the cookie-theft demo the injected script
# sends the victim's cookie here; a real attack would use the attacker's own
# server. Kept in memory so demo_xss.py can inspect what was received.
STOLEN_COOKIES = []

# Strict policy for the secure XSS pages: scripts only from this app,
# no inline scripts, no plugins. Bootstrap CSS comes from jsDelivr.
SECURE_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' https://cdn.jsdelivr.net; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)


def harden_session_cookie(app):
    """Defense 2: keep the session cookie away from page scripts.

    HttpOnly stops page scripts, and therefore any injected XSS payload, from
    reading the session cookie through document.cookie. It is the defense, so
    it is on in hardened mode and off in vulnerable mode. That matches the
    project's vulnerable/hardened split and lets the cookie-theft demo show a
    real before and after. SameSite=Lax also stops the cookie riding along on
    cross-site POSTs, so it is hardened-mode only too: in vulnerable mode it
    would block the CSRF module's cross-site attack page.
    """
    app.config['SESSION_COOKIE_HTTPONLY'] = not misconfig.VULNERABLE
    app.config['SESSION_COOKIE_SAMESITE'] = None if misconfig.VULNERABLE else 'Lax'


def secure_page(html):
    """Defense 1: send the secure XSS pages with a strict CSP."""
    resp = make_response(html)
    resp.headers['Content-Security-Policy'] = SECURE_CSP
    return resp


@xss_bp.route('/xss/attacker/steal')
def attacker_steal():
    """Stand-in for an attacker's server; the stored-XSS payload points here."""
    cookie = request.args.get('c', '')
    STOLEN_COOKIES.append(cookie)
    print(f"[attacker] received cookie: {cookie!r}", flush=True)
    return '', 204


@xss_bp.route('/xss/attacker/log')
def attacker_log():
    """What the attacker has collected so far, for showing the theft live."""
    return jsonify(stolen_cookies=STOLEN_COOKIES)


def init_reviews_table():
    conn = get_db()
    conn.execute(
        'CREATE TABLE IF NOT EXISTS reviews ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER, '
        'username TEXT, body TEXT, version TEXT)'
    )
    conn.commit()
    conn.close()


# ==========================================
# 1. REFLECTED XSS: product search
# ==========================================

@xss_bp.route('/xss/vulnerable/search')
def search_vulnerable():
    q = request.args.get('q', '')
    # VULNERABLE: the search term goes straight into the page.
    return render_template('xss_search.html', q=q, safe=False, user=session.get('user'))


@xss_bp.route('/xss/secure/search')
def search_secure():
    q = request.args.get('q', '')
    # SECURE: same page, but rendered through Jinja's normal auto-escaping,
    # with q also handed to JavaScript through |tojson (see template),
    # and sent with a strict CSP.
    return secure_page(
        render_template('xss_search.html', q=q, safe=True, user=session.get('user'))
    )


# ==========================================
# 2. STORED XSS: product reviews
# ==========================================

@xss_bp.route('/xss/vulnerable/reviews', methods=['GET', 'POST'])
def reviews_vulnerable():
    if request.method == 'POST':
        if 'user' not in session:
            return redirect(url_for('login'))
        body = request.form.get('body', '')
        conn = get_db()
        conn.execute(
            'INSERT INTO reviews (product_id, username, body, version) VALUES (?, ?, ?, ?)',
            (1, session['user'], body, 'vulnerable'),
        )
        conn.commit()
        conn.close()
        return redirect(url_for('xss.reviews_vulnerable'))

    conn = get_db()
    rows = conn.execute(
        "SELECT username, body FROM reviews WHERE version = 'vulnerable' ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template(
        'xss_reviews.html', reviews=rows, safe=False,
        user=session.get('user'), action=url_for('xss.reviews_vulnerable'),
    )


@xss_bp.route('/xss/secure/reviews', methods=['GET', 'POST'])
def reviews_secure():
    if request.method == 'POST':
        if 'user' not in session:
            return redirect(url_for('login'))
        # Mitigation: trim and cap the input before it's even stored.
        body = request.form.get('body', '').strip()[:300]
        if body:
            conn = get_db()
            conn.execute(
                'INSERT INTO reviews (product_id, username, body, version) VALUES (?, ?, ?, ?)',
                (1, session['user'], body, 'secure'),
            )
            conn.commit()
            conn.close()
        return redirect(url_for('xss.reviews_secure'))

    conn = get_db()
    rows = conn.execute(
        "SELECT username, body FROM reviews WHERE version = 'secure' ORDER BY id DESC"
    ).fetchall()
    conn.close()
    # Mitigation: rows go straight to the template, which auto-escapes
    # them on output (see xss_reviews.html) instead of trusting |safe.
    return secure_page(render_template(
        'xss_reviews.html', reviews=rows, safe=True,
        user=session.get('user'), action=url_for('xss.reviews_secure'),
    ))