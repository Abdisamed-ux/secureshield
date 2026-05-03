"""
SecureShield API Test Suite
Run this to verify all tasks work correctly.
Start the server first: python app.py
"""
import requests
import json

BASE = "http://127.0.0.1:5000"

def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print('='*55)

def show(label, resp):
    print(f"\n[{label}] {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except Exception:
        print(resp.text)

# ─────────────────────────────────────────────
section("TASK 1 & 2 — Register + Login")
# ─────────────────────────────────────────────

# Register a regular user
r = requests.post(f"{BASE}/register", json={"username": "alice", "password": "pass123", "role": "user"})
show("Register alice (user)", r)

# Register another user (to delete later)
r = requests.post(f"{BASE}/register", json={"username": "bob", "password": "pass456", "role": "user"})
show("Register bob (user)", r)

# Login as admin (pre-seeded)
r = requests.post(f"{BASE}/login", json={"username": "admin", "password": "admin123"})
show("Login admin", r)
admin_token = r.json().get("token")

# Login as alice
r = requests.post(f"{BASE}/login", json={"username": "alice", "password": "pass123"})
show("Login alice", r)
alice_token = r.json().get("token")

# ─────────────────────────────────────────────
section("TASK 3 — Token Validation")
# ─────────────────────────────────────────────

# No token
r = requests.get(f"{BASE}/profile")
show("GET /profile (no token)", r)

# Invalid token
r = requests.get(f"{BASE}/profile", headers={"Authorization": "Bearer fake.token.here"})
show("GET /profile (invalid token)", r)

# ─────────────────────────────────────────────
section("TASK 4 — Role-Based Routing")
# ─────────────────────────────────────────────

# Alice (user) accesses /profile  → allowed
r = requests.get(f"{BASE}/profile", headers={"Authorization": f"Bearer {alice_token}"})
show("GET /profile as alice (user) → 200", r)

# Admin accesses /profile  → allowed
r = requests.get(f"{BASE}/profile", headers={"Authorization": f"Bearer {admin_token}"})
show("GET /profile as admin → 200", r)

# Alice (user) tries DELETE → should be 403
r = requests.delete(f"{BASE}/user/999", headers={"Authorization": f"Bearer {alice_token}"})
show("DELETE /user/999 as alice (user) → 403 FORBIDDEN", r)

# Admin deletes bob (find bob's id first)
r = requests.get(f"{BASE}/users", headers={"Authorization": f"Bearer {admin_token}"})
users = r.json().get("users", [])
bob = next((u for u in users if u["username"] == "bob"), None)
if bob:
    r = requests.delete(f"{BASE}/user/{bob['id']}", headers={"Authorization": f"Bearer {admin_token}"})
    show(f"DELETE /user/{bob['id']} (bob) as admin → 200", r)

# ─────────────────────────────────────────────
section("TASK 5 — Token Revocation / Logout")
# ─────────────────────────────────────────────

# Logout alice
r = requests.post(f"{BASE}/logout", headers={"Authorization": f"Bearer {alice_token}"})
show("POST /logout alice", r)

# Try to use alice's revoked token
r = requests.get(f"{BASE}/profile", headers={"Authorization": f"Bearer {alice_token}"})
show("GET /profile with revoked token → 401", r)

# ─────────────────────────────────────────────
section("TASK 6 — Check security.log")
# ─────────────────────────────────────────────
import os, time
time.sleep(0.2)
log_path = os.path.join(os.path.dirname(__file__), "security.log")
if os.path.exists(log_path):
    print(f"\n[security.log contents]")
    with open(log_path) as f:
        print(f.read())
else:
    print("security.log not found (run from the secureshield directory)")
