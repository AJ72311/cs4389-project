from app import app

ATTACKS = {
    "normal": "Laptop",
    "dump_products": "' OR 1=1 --",
    "dump_users": "' UNION SELECT id, username, password, role FROM users --",
}


def banner(text):
    print("\n" + "=" * 70 + "\n" + text + "\n" + "=" * 70)


def login(client, username, password):
    client.post("/login", data={"username": username, "password": password})


def run(version):
    banner(version.upper() + ": product search")
    c = app.test_client()
    login(c, "alice", "password123")
    results = {}
    for label, text in ATTACKS.items():
        r = c.get("/api/" + version + "/products/search", query_string={"name": text})
        results[label] = r.get_json()
        print(label + ":", repr(text), "->", r.status_code, len(results[label]), "rows")
    return results


def verdict(v, s):
    dumped = len(v["dump_products"]) > len(v["normal"])
    leaked = any(row["name"] == "admin" and row["price"] == "admin123" for row in v["dump_users"])
    blocked = s["dump_products"] == [] and s["dump_users"] == [] and len(s["normal"]) == 1
    return dumped and leaked, blocked


if __name__ == "__main__":
    v = run("vulnerable")
    s = run("secure")
    works, blocked = verdict(v, s)

    banner("SUMMARY")
    print("Vulnerable: attacks returned extra rows and leaked the admin password ->", works)
    print("Secure: both attacks returned nothing, normal search still works ->", blocked)

    assert works and blocked
    print("\nAll checks passed.")
