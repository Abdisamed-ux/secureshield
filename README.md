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
