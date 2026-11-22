from app import app


def banner(text):
    print("\n" + "=" * 70 + "\n" + text + "\n" + "=" * 70)


def login(client, username, password):
    client.post("/login", data={"username": username, "password": password})


def get(client, path):
    r = client.get(path)
    print(path, "->", r.status_code, r.get_json())
    return r.status_code, r.get_json()


def vulnerable_demo():
    banner("VULNERABLE: no ownership or role checks")
    alice = app.test_client()
    login(alice, "alice", "password123")
    return {
        "other": get(alice, "/api/vulnerable/user/1"),
        "everyone": get(alice, "/api/vulnerable/admin/users"),
    }


def secure_demo():
    banner("SECURE: ownership and role checks")
    alice = app.test_client()
    login(alice, "alice", "password123")
    admin = app.test_client()
    login(admin, "admin", "admin123")
    return {
        "other": get(alice, "/api/secure/user/1"),
        "own": get(alice, "/api/secure/user/2"),
        "everyone": get(alice, "/api/secure/admin/users"),
        "admin_list": get(admin, "/api/secure/admin/users"),
        "anonymous": get(app.test_client(), "/api/secure/user/2"),
    }


def verdict(v, s):
    leaked = v["other"][0] == 200 and "password" in v["other"][1] and v["everyone"][0] == 200 and len(v["everyone"][1]) > 1
    blocked = s["other"][0] == 403 and s["everyone"][0] == 403 and s["anonymous"][0] == 401
    normal = s["own"][0] == 200 and "password" not in s["own"][1] and s["admin_list"][0] == 200 and all("password" not in user for user in s["admin_list"][1])
    return leaked, blocked and normal


if __name__ == "__main__":
    v = vulnerable_demo()
    s = secure_demo()
    works, blocked = verdict(v, s)

    banner("SUMMARY")
    print("Vulnerable: alice read the admin's account and listed every user ->", works)
    print("Secure: alice blocked (403), logged-out blocked (401), own profile and admin list still work ->", blocked)

    assert works and blocked
    print("\nAll checks passed.")
