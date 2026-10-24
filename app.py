from flask import Flask, render_template, request, redirect, url_for, session
from database import get_db, init_db
import misconfig # Marc: debug leaks and permissive headers.
import deserialization # Shreya: cart cookie deserialization demo and fix
import idor # Prajit: IDOR demo and session-ownership mitigation, Role BAC bypass demo and its admin-role verification fix
import xss # Nitin: reflected/stored XSS demo and output-encoding fix

app = Flask(__name__)
app.secret_key = 'key-123'

init_db()
misconfig.init_app(app) # Marc: registers routes, headers, and hardened mode handlers

app.register_blueprint(idor.idor_bp) # Prajit: Registers the blueprint

deserialization.init_orders_table()
app.register_blueprint(deserialization.deser_bp) # Shreya: insecure deserialization (cart cookie tampering) and signed/validated fix

xss.init_reviews_table()
app.register_blueprint(xss.xss_bp) # Nitin: reflected search + stored reviews XSS

@app.route('/')
def index():
    conn = get_db()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template('index.html', products=products, user=session.get('user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        
        if user:
            session['user'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials'
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=misconfig.VULNERABLE, port=5000)  
