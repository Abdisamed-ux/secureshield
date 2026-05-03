"""
SecureShield — RBAC API (Mini Project II)
Flask + JWT + bcrypt + SQLite
"""

import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, request
from flask_bcrypt import Bcrypt

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secureshield.db"
SECURITY_LOG = BASE_DIR / "security.log"

app = Flask(__name__)
# Use a long random secret in production (env); default is dev-only, 32+ chars for HS256.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-insecure-key-please-set-SECRET_KEY-32chars-min",
)
app.config["JWT_EXPIRATION_HOURS"] = int(os.environ.get("JWT_EXPIRATION_HOURS", "24"))

bcrypt = Bcrypt(app)

# In-memory JWT blacklist (jti -> revoked)
_token_blacklist: set[str] = set()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'admin'))
        )
        """
    )
    conn.commit()

    # Seed default admin if none exists (demo / coursework)
    row = conn.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
    if row is None:
        admin_user = os.environ.get("SEED_ADMIN_USERNAME", "admin")
        admin_pass = os.environ.get("SEED_ADMIN_PASSWORD", "admin123")
        pw_hash = bcrypt.generate_password_hash(admin_pass).decode("utf-8")
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (admin_user, pw_hash),
        )
        conn.commit()
    conn.close()


def _extract_bearer_token() -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[7:].strip() or None


def _decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            app.config["SECRET_KEY"],
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _extract_bearer_token()
        if not token:
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        payload = _decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        jti = payload.get("jti")
        if jti and jti in _token_blacklist:
            return jsonify({"error": "Token has been revoked"}), 401
        g.jwt_payload = payload
        g.current_username = payload.get("username")
        g.current_role = payload.get("role")
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if (g.current_role or "").lower() != "admin":
            return jsonify({"error": "Forbidden: admin role required"}), 403
        return f(*args, **kwargs)

    return decorated


@app.after_request
def log_forbidden_attempts(response):
    if response.status_code == 403:
        line = (
            f"{datetime.now(timezone.utc).isoformat()} | "
            f"{request.method} {request.path} | 403 Forbidden | "
            f"remote={request.remote_addr}\n"
        )
        SECURITY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(SECURITY_LOG, "a", encoding="utf-8") as logf:
            logf.write(line)
    return response


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            (username, pw_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already exists"}), 409
    conn.close()
    return jsonify({"message": "User registered", "username": username, "role": "user"}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    conn = get_db()
    row = conn.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    if not row or not bcrypt.check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    jti = str(uuid.uuid4())
    exp = datetime.now(timezone.utc) + timedelta(hours=app.config["JWT_EXPIRATION_HOURS"])
    token = jwt.encode(
        {
            "username": row["username"],
            "role": row["role"],
            "jti": jti,
            "exp": exp,
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    return jsonify(
        {
            "token": token,
            "token_type": "Bearer",
            "expires_at": exp.isoformat(),
        }
    )


@app.post("/logout")
@token_required
def logout():
    jti = g.jwt_payload.get("jti")
    if jti:
        _token_blacklist.add(jti)
    return jsonify({"message": "Logged out; token invalidated"})


@app.get("/profile")
@token_required
def profile():
    return jsonify(
        {
            "username": g.current_username,
            "role": g.current_role,
        }
    )


@app.delete("/user/<int:user_id>")
@admin_required
def delete_user(user_id):
    conn = get_db()
    cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    if deleted == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": f"User {user_id} deleted"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
