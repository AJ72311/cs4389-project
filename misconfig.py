"""
Security misconfiguration module (Marc): debug leaks and permissive headers.

Plug into the shared app with two lines in app.py:

    import misconfig
    misconfig.init_app(app)

Mode is chosen with the APP_MODE environment variable:

  vulnerable (default) : the app's baseline. Debug mode on, weak secret key,
                         leftover debug route, version banner, and a CORS policy
                         that trusts every origin.
  hardened             : debug off, generic errors with an error ID, details
                         logged server side only, security headers, CORS
                         allowlist, strong secret key, no debug route.

Run on localhost only. The Werkzeug debugger in vulnerable mode can run code
on the server.
"""

import logging
import os
import uuid
from importlib.metadata import version

from flask import Blueprint, abort, current_app, jsonify, request, session
from werkzeug.exceptions import HTTPException

from database import get_db

# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------
MODE = os.environ.get("APP_MODE", "vulnerable").lower()
if MODE not in ("vulnerable", "hardened"):
    raise SystemExit("APP_MODE must be 'vulnerable' or 'hardened'")
VULNERABLE = MODE == "vulnerable"

# Origins allowed to call the app from a browser in hardened mode.
ALLOWED_ORIGINS = set(
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000").split(",")
    if o.strip()
)

bp = Blueprint("misconfig", __name__)


# ---------------------------------------------------------------------------
# Routes used to demonstrate the misconfigurations
# ---------------------------------------------------------------------------
@bp.route("/api/products/<int:product_id>")
def get_product(product_id):
    """Crashes for an unknown ID: fetchone() returns None and indexing it fails."""
    conn = get_db()
    row = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()
    return jsonify(id=row["id"], name=row["name"], price=row["price"])


@bp.route("/crash/divide")
def crash_divide():
    return jsonify(result=1 / 0)


@bp.route("/api/profile")
def profile():
    """Private data for the logged in user. Target of the CORS demo."""
    username = session.get("user")
    if not username:
        abort(401)
    return jsonify(username=username, role=session.get("role"))


@bp.route("/debug/config")
def debug_config():
    """Misconfiguration: leftover debug route. Fix: it does not exist when hardened."""
    if not VULNERABLE:
        abort(404)
    return jsonify(
        mode=MODE,
        debug=current_app.debug,
        secret_key=current_app.secret_key,
        database="shop.db",
        working_directory=os.getcwd(),
    )


# ---------------------------------------------------------------------------
# Error handling (registered in hardened mode only)
# ---------------------------------------------------------------------------
def handle_error(error):
    error_id = uuid.uuid4().hex[:8]
    if isinstance(error, HTTPException):
        current_app.logger.info(
            "error_id=%s status=%s path=%s", error_id, error.code, request.path
        )
        return jsonify(error=error.name, error_id=error_id), error.code
    current_app.logger.error(
        "error_id=%s path=%s unhandled exception",
        error_id,
        request.path,
        exc_info=error,
    )
    return jsonify(error="Something went wrong", error_id=error_id), 500


# ---------------------------------------------------------------------------
# Headers and CORS (applied to every response, including other members' routes)
# ---------------------------------------------------------------------------
def add_headers(response):
    origin = request.headers.get("Origin")

    if VULNERABLE:
        # Misconfiguration: announce the software and version.
        response.headers["X-Powered-By"] = "Flask " + version("flask")
        # Misconfiguration: trust every origin and allow cookies to be sent.
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        # Note: the Flask development server adds its own Server banner that the
        # app cannot remove. A production server or reverse proxy hides it.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        # HSTS only has an effect over HTTPS.
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        # CORS allowlist: only listed origins get access headers.
        response.headers["Vary"] = "Origin"
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"

    return response


# ---------------------------------------------------------------------------
# Entry point called from the main app
# ---------------------------------------------------------------------------
def init_app(app):
    logging.basicConfig(
        filename="app.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    app.register_blueprint(bp)
    app.after_request(add_headers)

    if not VULNERABLE:
        # Replace the weak hardcoded secret key with a strong one.
        app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
        # Catch every error so nothing technical reaches the browser.
        app.register_error_handler(Exception, handle_error)