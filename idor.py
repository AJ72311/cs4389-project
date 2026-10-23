from flask import Blueprint, jsonify, session, request
from database import get_db

idor_bp = Blueprint('idor', __name__)

# ==========================================
# 1. HORIZONTAL PRIVILEGE ESCALATION (IDOR)
# ==========================================

@idor_bp.route('/api/vulnerable/user/<int:user_id>', methods=['GET'])
def get_user_vulnerable(user_id):
    # Enforce Authentication (There must be an active session)
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: Fetches profile by ID without checking if it belongs to the logged-in user.
    conn = get_db()
    user = conn.execute('SELECT id, username, role, password FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        return jsonify(dict(user))
    return jsonify({'error': 'User not found'}), 404

@idor_bp.route('/api/secure/user/<int:user_id>', methods=['GET'])
def get_user_secure(user_id):
    # SECURE: Verifies the requested profile belongs to the authenticated session.
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    user = conn.execute('SELECT id, username, role, password FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Mitigation: Strict server-side authorization check (Ownership)
    if user['username'] != session['user']:
        return jsonify({'error': 'Forbidden: You can only access your own profile'}), 403

    return jsonify(dict(user))

# ==========================================
# 2. VERTICAL PRIVILEGE ESCALATION (ROLE BAC)
# ==========================================

@idor_bp.route('/api/vulnerable/admin/users', methods=['GET'])
def get_all_users_vulnerable():
    # VULNERABLE: Requires login, but fails to verify if the user has Admin privileges.
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    # Flaw: A regular 'customer' can hit this endpoint and dump all users.
    conn = get_db()
    users = conn.execute('SELECT id, username, role, password FROM users').fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users])

@idor_bp.route('/api/secure/admin/users', methods=['GET'])
def get_all_users_secure():
    # SECURE: Enforces strict Role-Based Access Control (RBAC).
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    # Mitigation: Verify the session role is exactly 'admin'
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden: Administrator access required'}), 403

    conn = get_db()
    users = conn.execute('SELECT id, username, role, password FROM users').fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users])
