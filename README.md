# SecureShield — Mini Project II (RBAC API)

Flask-based secure backend implementing JWT authentication and role-based access control (RBAC).

## Features Implemented

- `POST /register` — register standard users with bcrypt-hashed passwords (SQLite storage).
- `POST /login` — authenticate and issue JWT (`username`, `role`, `jti`, `exp`).
- `POST /logout` — revoke active token by blacklisting its `jti`.
- `GET /profile` — protected route accessible by authenticated `user` and `admin`.
- `DELETE /user/<id>` — protected admin-only route.
- Defensive logging: all `403 Forbidden` responses are logged to `security.log`.

## Tech Stack

- Flask
- Flask-Bcrypt
- PyJWT
- SQLite (local file DB)

## Project Files

- `app.py` — main API implementation.
- `requirements.txt` — dependencies.
- `REPORT.md` — brief report required by assignment.
- `security.log` — generated at runtime for forbidden attempts.

## Setup

```bash
cd /Users/abdismed/secureshield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Server runs by default at: `http://127.0.0.1:5000`

## Seed Admin (for demo)

The app seeds an admin account if none exists:

- Username: `admin`
- Password: `admin123`

Override with env vars before starting:

```bash
export SEED_ADMIN_USERNAME="your_admin_name"
export SEED_ADMIN_PASSWORD="your_admin_password"
```

## Required Demo Flow (for video)

### 1) Successful login

```bash
curl -s -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 2) Access denied (user tries admin route)

Register/login normal user:

```bash
curl -s -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
```

Use returned user token for admin delete endpoint:

```bash
curl -i -X DELETE http://127.0.0.1:5000/user/1 \
  -H "Authorization: Bearer <USER_TOKEN>"
```

Expected: `403 Forbidden`

### 3) Tamper test

- Copy a valid token to [jwt.io](https://jwt.io)
- Manually change `"role": "user"` to `"role": "admin"` without re-signing
- Send tampered token to `/profile` or `/user/<id>`
- Expected: invalid token/signature rejection (`401`)

## Security Notes

- Passwords are never stored in plaintext (bcrypt hash only).
- JWT payload must not store sensitive secrets (passwords, private keys, etc.).
- Principle of least privilege is enforced through role checks on protected routes.

# SecureShield — RBAC API

A Python Flask application implementing JWT authentication and Role-Based Access Control.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

The server starts on `http://127.0.0.1:5000`.  
A default **admin** account is seeded automatically: `admin / admin123`

## API Endpoints

| Method | Endpoint | Access | Description |
|--------|----------|--------|-------------|
| GET | `/` | Public | API info |
| POST | `/register` | Public | Register a new user |
| POST | `/login` | Public | Get a JWT token |
| POST | `/logout` | Any authenticated | Revoke token (blacklist) |
| GET | `/profile` | User & Admin | View own profile |
| DELETE | `/user/<id>` | Admin only | Delete a user |
| GET | `/users` | Admin only | List all users |

## Authentication

Include the JWT in every protected request:

```
Authorization: Bearer <your_token>
```

## Example Workflow

```bash
# 1. Register a user
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123","role":"user"}'

# 2. Login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
# → copy the "token" value

# 3. Access profile
curl http://localhost:5000/profile \
  -H "Authorization: Bearer <token>"

# 4. Try admin route (should 403)
curl -X DELETE http://localhost:5000/user/1 \
  -H "Authorization: Bearer <token>"

# 5. Logout (revoke token)
curl -X POST http://localhost:5000/logout \
  -H "Authorization: Bearer <token>"
```

## Task Coverage

| Task | Feature | Status |
|------|---------|--------|
| 1 | bcrypt password hashing | ✅ |
| 2 | JWT issuance on login | ✅ |
| 3 | JWT validation middleware | ✅ |
| 4 | Role-based routing (User/Admin) | ✅ |
| 5 | Token blacklist (logout) | ✅ |
| 6 | Security logging to security.log | ✅ |

## Tamper Test (for video demo)

1. Login and copy the token
2. Paste into https://jwt.io
3. Change `"role": "user"` → `"role": "admin"` in the payload
4. Copy the modified token (without re-signing)
5. Use it in a DELETE request — server returns **401 Invalid token**
