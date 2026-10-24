"""
SQL injection module example

Scenario: the catalogue has a search feature that filters products by name.
The search term arrives in the query string and has to end up inside a LIKE
pattern, i.e. inside a SQL string literal. To demonstrate, there's both a
secure and vulnerable endpoint

Vulnerable  (/api/vulnerable/products/search)
The term is interpolated into the SQL text before the statement is
handed to SQLite, so the client controls part of the query:

Secure      (/api/secure/products/search)
Mitigation: parameterized queries. The statement is compiled with a ?
placeholder and the term is bound as data, so user input can never
change the query structure.
"""

from flask import Blueprint, jsonify, request, session

from database import get_db

sqli_bp = Blueprint("sqli", __name__)

# The vulnerable example of user input added raw into a SQL query
@sqli_bp.route("/api/vulnerable/products/search", methods=["GET"])
def search_vulnerable():
    # Enforce Authentication (There must be an active session)
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    name = request.args.get("name", "")

    # The vulnerable line itself
    query = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{name}%'"

    conn = get_db()
    rows = conn.execute(query).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


# The secure API route example that correctly parameterizes its query
@sqli_bp.route("/api/secure/products/search", methods=["GET"])
def search_secure():
    # Enforce Authentication (There must be an active session)
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    name = request.args.get("name", "")

    # Fix the vulnerability by
    term = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{term}%"

    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, price, description FROM products WHERE name LIKE ? ESCAPE '\\'",
        (pattern,),
    ).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])
