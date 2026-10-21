import sqlite3

def get_db():
    conn = sqlite3.connect('shop.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect('shop.db')
    c = conn.cursor()
    
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, description TEXT)')
    
    c.execute('SELECT * FROM users WHERE username = "admin"')
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password, role) VALUES ("admin", "admin123", "admin")')
        c.execute('INSERT INTO users (username, password, role) VALUES ("alice", "password123", "customer")')

    c.execute('SELECT * FROM products')
    if not c.fetchall():
        c.execute('INSERT INTO products (name, price, description) VALUES ("Laptop", 999.99, "Gaming laptop")')
        c.execute('INSERT INTO products (name, price, description) VALUES ("Phone", 499.99, "Smartphone")')
        c.execute('INSERT INTO products (name, price, description) VALUES ("Headphones", 79.99, "Wireless headphones")')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()