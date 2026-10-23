"""
Insecure deserialization module (OWASP A08: Software and Data Integrity Failures).
Owner: Shreya Balaji

Scenario: the shopping cart is stored client side, in a cookie that holds a
serialized cart object. The server later deserializes that cookie and acts on it.

  Vulnerable  (/api/vulnerable/cart...)
      The cart is base64-encoded JSON with no integrity protection. It carries
      the buyer's username and each item's price, and the server trusts every
      field it deserializes. A user can decode the cookie, edit it, re-encode it,
      and the server will:
        - charge whatever price the cookie says (price tampering), and
        - record the order under whatever username the cookie says (identity
          tampering).

  Secure      (/api/secure/cart...)
      Defense in depth:
        1. Integrity: the cookie is signed with the app's secret key
           (itsdangerous, which ships with Flask). Any edit breaks the signature
           and the cookie is rejected.
        2. Minimal state: the cookie holds only product IDs and quantities.
           No prices, no usernames, nothing the server should decide itself.
        3. Allowlist validation: after the signature check, the payload must
           match an exact schema (allowed keys, integer types, bounded
           quantities, product IDs that exist). Anything else is rejected.
        4. Server-side truth: prices come from the database and the buyer comes
           from the authenticated Flask session, never from the cookie.

Why not pickle: Python's pickle can run arbitrary code while loading, so it
must never be used on data a client can modify. Both versions here use JSON
so the demo stays safe to run; the vulnerable version still shows the core
flaw, which is trusting deserialized client data.
"""

import base64
import json

from flask import Blueprint, current_app, jsonify, make_response, request, session
from itsdangerous import BadSignature, URLSafeSerializer

from database import get_db

deser_bp = Blueprint("deserialization", __name__)

VULN_COOKIE = "cart_v"
SECURE_COOKIE = "cart_s"
MAX_QTY = 10
MAX_LINES = 20


def init_orders_table():
    """Orders table used by both checkout routes."""
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS orders ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, total REAL, "
        "items TEXT, version TEXT)"
    )
    conn.commit()
    conn.close()


def _get_product(product_id):
    conn = get_db()
    row = conn.execute(
        "SELECT id, name, price FROM products WHERE id = ?", (product_id,)
    ).fetchone()
    conn.close()
    return row


def _save_order(username, total, items, version):
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO orders (username, total, items, version) VALUES (?, ?, ?, ?)",
        (username, total, json.dumps(items), version),
    )
    conn.commit()
    order_id = cur.lastrowid
    conn.close()
    return order_id


def _read_add_request():
    data = request.get_json(silent=True) or {}
    product_id, qty = data.get("product_id"), data.get("qty", 1)
    if not isinstance(product_id, int) or not isinstance(qty, int):
        return None, None
    return product_id, qty


# ==========================================
# 1. VULNERABLE: unsigned, trusted cart object
# ==========================================

def _vuln_load(raw):
    # VULNERABLE: decodes and trusts whatever the client sent.
    if not raw:
        return None
    return json.loads(base64.b64decode(raw))


def _vuln_dump(cart):
    return base64.b64encode(json.dumps(cart).encode()).decode()


@deser_bp.route("/api/vulnerable/cart/add", methods=["POST"])
def vuln_add():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    product_id, qty = _read_add_request()
    product = _get_product(product_id) if product_id is not None else None
    if not product:
        return jsonify({"error": "Unknown product"}), 400

    cart = _vuln_load(request.cookies.get(VULN_COOKIE)) or {
        "user": session["user"],
        "items": [],
    }
    # Flaw: the price is copied into the client-held object.
    cart["items"].append(
        {"id": product["id"], "name": product["name"], "price": product["price"], "qty": qty}
    )
    resp = make_response(jsonify(cart))
    resp.set_cookie(VULN_COOKIE, _vuln_dump(cart))
    return resp


@deser_bp.route("/api/vulnerable/cart", methods=["GET"])
def vuln_view():
    cart = _vuln_load(request.cookies.get(VULN_COOKIE)) or {"items": []}
    return jsonify(cart)


@deser_bp.route("/api/vulnerable/checkout", methods=["POST"])
def vuln_checkout():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    cart = _vuln_load(request.cookies.get(VULN_COOKIE))
    if not cart or not cart.get("items"):
        return jsonify({"error": "Cart is empty"}), 400

    # Flaw: total and buyer both come from the deserialized client object.
    total = round(sum(i["price"] * i["qty"] for i in cart["items"]), 2)
    order_id = _save_order(cart["user"], total, cart["items"], "vulnerable")
    resp = make_response(
        jsonify({"order_id": order_id, "charged_user": cart["user"], "total": total})
    )
    resp.delete_cookie(VULN_COOKIE)
    return resp


# ==========================================
# 2. SECURE: signed, minimal, validated cart
# ==========================================

def _signer():
    return URLSafeSerializer(current_app.secret_key, salt="cart-v1")


def _secure_load(raw):
    """Returns a list of {"id", "qty"} or raises ValueError."""
    if not raw:
        return []
    try:
        data = _signer().loads(raw)  # Mitigation 1: integrity check
    except BadSignature:
        raise ValueError("Cart cookie failed signature check")

    # Mitigation 3: strict allowlist validation of the structure.
    if not isinstance(data, dict) or set(data) != {"items"}:
        raise ValueError("Unexpected cart structure")
    items = data["items"]
    if not isinstance(items, list) or len(items) > MAX_LINES:
        raise ValueError("Invalid item list")
    for item in items:
        if not isinstance(item, dict) or set(item) != {"id", "qty"}:
            raise ValueError("Unexpected item fields")
        if not isinstance(item["id"], int) or not isinstance(item["qty"], int):
            raise ValueError("Item fields must be integers")
        if not 1 <= item["qty"] <= MAX_QTY:
            raise ValueError("Quantity out of range")
    return items


def _secure_dump(items):
    # Mitigation 2: only IDs and quantities leave the server.
    return _signer().dumps({"items": items})


def _priced(items):
    """Mitigation 4: prices come from the database."""
    lines = []
    for item in items:
        product = _get_product(item["id"])
        if not product:
            raise ValueError("Unknown product in cart")
        lines.append(
            {"id": product["id"], "name": product["name"], "price": product["price"], "qty": item["qty"]}
        )
    return lines


def _reject(msg):
    current_app.logger.warning("deserialization: rejected cart cookie (%s)", msg)
    resp = make_response(jsonify({"error": "Invalid cart, it has been cleared"}), 400)
    resp.delete_cookie(SECURE_COOKIE)
    return resp


@deser_bp.route("/api/secure/cart/add", methods=["POST"])
def secure_add():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    product_id, qty = _read_add_request()
    if product_id is None or not 1 <= qty <= MAX_QTY or not _get_product(product_id):
        return jsonify({"error": "Invalid product or quantity"}), 400
    try:
        items = _secure_load(request.cookies.get(SECURE_COOKIE))
    except ValueError as e:
        return _reject(str(e))
    items.append({"id": product_id, "qty": qty})
    if len(items) > MAX_LINES:
        return jsonify({"error": "Cart is full"}), 400
    resp = make_response(jsonify({"items": _priced(items)}))
    resp.set_cookie(SECURE_COOKIE, _secure_dump(items), httponly=True, samesite="Lax")
    return resp


@deser_bp.route("/api/secure/cart", methods=["GET"])
def secure_view():
    try:
        items = _priced(_secure_load(request.cookies.get(SECURE_COOKIE)))
    except ValueError as e:
        return _reject(str(e))
    return jsonify({"items": items})


@deser_bp.route("/api/secure/checkout", methods=["POST"])
def secure_checkout():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        items = _priced(_secure_load(request.cookies.get(SECURE_COOKIE)))
    except ValueError as e:
        return _reject(str(e))
    if not items:
        return jsonify({"error": "Cart is empty"}), 400

    total = round(sum(i["price"] * i["qty"] for i in items), 2)
    buyer = session["user"]  # Mitigation 4: identity from the session only
    order_id = _save_order(buyer, total, items, "secure")
    resp = make_response(jsonify({"order_id": order_id, "charged_user": buyer, "total": total}))
    resp.delete_cookie(SECURE_COOKIE)
    return resp
