# SecureShield — Brief Report (Mini Project II)

## 1. Why salting is necessary to prevent rainbow table attacks

A **rainbow table** is a precomputed list of hash outputs for many common passwords. If passwords are hashed without a salt, every user who chose `password123` shares the same hash. An attacker can look up that hash in a rainbow table and recover the password instantly.

A **salt** is a unique, random value stored with each password. The hash is computed over `salt + password` (or a proper KDF input that includes the salt). That means two users with the same password get different hashes, so bulk precomputation no longer applies: the attacker would need a separate table per salt, which is impractical. Modern password APIs (e.g. bcrypt) incorporate salting and a slow work factor so offline guessing stays expensive.

## 2. Risks of storing sensitive data inside a JWT payload

JWT payloads are only **Base64URL-encoded**, not encrypted. Anyone who obtains the token can read the claims. Putting secrets (passwords, API keys) or highly sensitive PII in the payload exposes them to clients, proxies, and logs.

Even for non-secret claims like `role`, the payload is **tamper-evident** only if the signature is verified with a strong server secret. If verification is buggy or the secret leaks, tokens could be forged. Best practice: keep JWTs small—identifiers and coarse roles—and load authoritative user data from the database when needed; never put passwords or equivalent secrets in the token.
