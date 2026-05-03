"""
SecureShield - Role-Based Access Control (RBAC) API
Flask application implementing JWT authentication and role-based access control.
"""

import jwt
import json
import logging
import sqlite3
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_bcrypt import Bcrypt

# ─────────────────────────────────────────────
#  App Configuration
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "super-secret-dev-key-change-in-production")
app.config["JWT_EXPIRY_HOURS"] = 1

bcrypt = Bcrypt(app)

# ─────────────────────────────────────────────
#  Task 6: Defensive Logging Setup
# ─────────────────────────────────────────────
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.WARNING)
file_handler = logging.FileHandler("security.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
security_logger.addHandler(file_handler)

# ─────────────────────────────────────────────
#  Task 5: In-Memory Token Blacklist
# ─────────────────────────────────────────────
token_blacklist: set[str] = set()

# ─────────────────────────────────────────────
#  Database Setup (SQLite)
# ─────────────────────────────────────────────
DATABASE = "users.db"

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Create users table and seed a default admin."""
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,
                role     TEXT    NOT NULL DEFAULT 'user'
            )
        """)
        db.commit()

        # Seed admin account if not exists
        existing = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not existing:
            hashed = bcrypt.generate_password_hash("admin123").decode("utf-8")
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", hashed, "admin")
            )
            db.commit()
            print("[INIT] Admin account created: admin / admin123")


init_db()

# ─────────────────────────────────────────────
#  Helper: Generate JWT
# ─────────────────────────────────────────────
def generate_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=app.config["JWT_EXPIRY_HOURS"]),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

# ─────────────────────────────────────────────
#  Task 3: JWT Validation Decorator
# ─────────────────────────────────────────────
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            security_logger.warning(
                f"MISSING_TOKEN | endpoint={request.path} | ip={request.remote_addr}"
            )
            return jsonify({"error": "Authorization header missing or malformed"}), 401

        token = auth_header.split(" ", 1)[1]

        # Task 5: Check blacklist
        if token in token_blacklist:
            security_logger.warning(
                f"REVOKED_TOKEN | endpoint={request.path} | ip={request.remote_addr}"
            )
            return jsonify({"error": "Token has been revoked. Please log in again."}), 401

        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError as e:
            security_logger.warning(
                f"INVALID_TOKEN | endpoint={request.path} | ip={request.remote_addr} | reason={e}"
            )
            return jsonify({"error": "Invalid token"}), 401

        # Store decoded payload + raw token for use in route handlers
        g.current_user = payload
        g.raw_token = token
        return f(*args, **kwargs)

    return decorated

# ─────────────────────────────────────────────
#  Task 4: Role-Based Access Decorator
# ─────────────────────────────────────────────
def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = g.current_user.get("role")
            if user_role not in allowed_roles:
                security_logger.warning(
                    f"FORBIDDEN | user={g.current_user.get('username')} "
                    f"| role={user_role} | attempted={request.path} "
                    f"| method={request.method} | ip={request.remote_addr}"
                )
                return jsonify({
                    "error": "Forbidden: insufficient privileges",
                    "your_role": user_role,
                    "required_roles": list(allowed_roles),
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─────────────────────────────────────────────
#  Task 6: Middleware — log every 403 attempt
# ─────────────────────────────────────────────
@app.after_request
def log_forbidden(response):
    if response.status_code == 403:
        security_logger.warning(
            f"403_FORBIDDEN_RESPONSE | path={request.path} | method={request.method} "
            f"| ip={request.remote_addr}"
        )
    return response

# ─────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({
        "app": "SecureShield RBAC API",
        "endpoints": {
            "POST /register": "Register a new user",
            "POST /login": "Authenticate and receive JWT",
            "POST /logout": "Revoke current JWT",
            "GET /profile": "Protected – User & Admin",
            "DELETE /user/<id>": "Protected – Admin only",
            "GET /users": "Protected – Admin only, list all users",
        }
    })


# ──── Task 1: Secure Registration ────
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    if role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400

    # Task 1: bcrypt salt + hash — never store plain text
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

    return jsonify({
        "message": f"User '{username}' registered successfully",
        "role": role,
        "password_storage": "bcrypt hashed (never plain text)"
    }), 201


# ──── Task 2: Login & JWT Issuance ────
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    # Constant-time comparison via bcrypt — prevents timing attacks
    if not user or not bcrypt.check_password_hash(user["password"], password):
        security_logger.warning(
            f"FAILED_LOGIN | username={username} | ip={request.remote_addr}"
        )
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user["id"], user["username"], user["role"])

    return jsonify({
        "message": "Login successful",
        "token": token,
        "token_type": "Bearer",
        "expires_in": f"{app.config['JWT_EXPIRY_HOURS']} hour(s)",
        "username": user["username"],
        "role": user["role"],
    }), 200


# ──── Task 5: Logout / Token Revocation ────
@app.route("/logout", methods=["POST"])
@jwt_required
def logout():
    token_blacklist.add(g.raw_token)
    return jsonify({
        "message": "Logged out successfully. Token has been revoked.",
        "blacklisted_tokens": len(token_blacklist),
    }), 200


# ──── Task 4: GET /profile — User & Admin ────
@app.route("/profile", methods=["GET"])
@jwt_required
@role_required("user", "admin")
def profile():
    user = g.current_user
    db = get_db()
    row = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user["sub"],)).fetchone()
    return jsonify({
        "message": "Profile retrieved successfully",
        "user": {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        }
    }), 200


# ──── Task 4: DELETE /user/<id> — Admin Only ────
@app.route("/user/<int:user_id>", methods=["DELETE"])
@jwt_required
@role_required("admin")
def delete_user(user_id: int):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": f"User with id={user_id} not found"}), 404

    # Prevent admin from deleting themselves
    if user_id == g.current_user["sub"]:
        return jsonify({"error": "Cannot delete your own account"}), 400

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    return jsonify({
        "message": f"User '{user['username']}' (id={user_id}) deleted successfully",
        "deleted_by": g.current_user["username"],
    }), 200


# ──── Bonus: GET /users — Admin only ────
@app.route("/users", methods=["GET"])
@jwt_required
@role_required("admin")
def list_users():
    db = get_db()
    rows = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify({
        "users": [dict(r) for r in rows],
        "total": len(rows),
    }), 200


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=9000)
