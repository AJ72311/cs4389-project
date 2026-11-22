import base64
import json

from flask import Blueprint, current_app, jsonify, render_template, session

import misconfig
import deserialization
import xss

walkthrough_bp = Blueprint('walkthrough', __name__)

@walkthrough_bp.app_context_processor
def inject_mode():
    version = 'vulnerable' if misconfig.VULNERABLE else 'secure'
    return {'vulnerable': misconfig.VULNERABLE, 'version': version, 'user': session.get('user')}

@walkthrough_bp.route('/mode/toggle', methods=['POST'])
def toggle_mode():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    misconfig.VULNERABLE = not misconfig.VULNERABLE
    misconfig.MODE = 'vulnerable' if misconfig.VULNERABLE else 'hardened'
    xss.harden_session_cookie(current_app)
    xss.STOLEN_COOKIES.clear()
    return jsonify({'vulnerable': misconfig.VULNERABLE})

@walkthrough_bp.route('/demo/sqli')
def sqli_guide():
    return render_template('demo_sqli.html')

@walkthrough_bp.route('/demo/idor')
def idor_guide():
    return render_template('demo_idor.html')

@walkthrough_bp.route('/demo/xss')
def xss_guide():
    return render_template('demo_xss.html')

@walkthrough_bp.route('/demo/deserialization')
def deserialization_guide():
    return render_template('demo_deserialization.html')

@walkthrough_bp.route('/demo/deserialization/tamper', methods=['POST'])
def tamper_cart():
    forged = {'user': 'admin', 'items': [{'id': 1, 'name': 'Laptop', 'price': 0.01, 'qty': 1}]}
    cookie = deserialization.VULN_COOKIE if misconfig.VULNERABLE else deserialization.SECURE_COOKIE
    response = jsonify(forged)
    response.set_cookie(cookie, base64.b64encode(json.dumps(forged).encode()).decode())
    return response

@walkthrough_bp.route('/demo/misconfig')
def misconfig_guide():
    return render_template('demo_misconfig.html')

@walkthrough_bp.route('/demo/dependencies')
def dependencies_guide():
    names = ['requirements-vuln.txt', 'audit-vuln.txt', 'requirements.txt', 'audit-patched.txt']
    files = {}
    for name in names:
        with open(name) as f:
            files[name] = f.read()
    return render_template('demo_dependencies.html', files=files)

@walkthrough_bp.route('/demo/csrf')
def csrf_guide():
    return render_template('demo_csrf.html')
