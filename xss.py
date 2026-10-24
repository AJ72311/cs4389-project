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
"""

from flask import Blueprint, redirect, render_template, request, session, url_for

from database import get_db

xss_bp = Blueprint('xss', __name__)


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
    # SECURE: same page, but rendered through Jinja's normal auto-escaping.
    return render_template('xss_search.html', q=q, safe=True, user=session.get('user'))


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
    return render_template(
        'xss_reviews.html', reviews=rows, safe=True,
        user=session.get('user'), action=url_for('xss.reviews_secure'),
    )