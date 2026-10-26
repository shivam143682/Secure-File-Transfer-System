# Project Codebase Guide (EXPLAINED.md)

This document is prepared specifically for B.Tech project presentations, viva examinations, and project report documentation. It explains every source file in simple English and provides an intuitive analogy for how encryption works in this system.

---

## Explanation of Files in `app/`

### 1. `app/config.py`
- **Module**: *System Configuration & Environment Module*
- **What it does**:
  1. Reads sensitive settings and secrets (database URL, JWT secret, master key, size limits) from the `.env` file.
  2. Uses Pydantic's `BaseSettings` to validate types so misconfigurations are caught immediately on startup.
  3. Ensures that confidential credentials are never hardcoded into Python source files.

### 2. `app/database.py`
- **Module**: *Database Connectivity & Session Management Module*
- **What it does**:
  1. Creates the SQLAlchemy 2.0 database engine connecting to PostgreSQL via `psycopg2`.
  2. Configures `SessionLocal`, which acts as a factory producing new database sessions.
  3. Provides the `get_db` generator dependency that allocates and cleanly closes a database session for every HTTP request.

### 3. `app/models.py`
- **Module**: *Database Models & Relational Schema Module*
- **What it does**:
  1. Defines the PostgreSQL tables: `users` (accounts), `file_transfers` (encrypted payloads), and `transfer_logs` (audit logs).
  2. Maps binary ciphertext directly to PostgreSQL `BYTEA` using SQLAlchemy's `LargeBinary`.
  3. Configures table relationships, foreign key constraints (`sender_id`, `receiver_id`), and auto-populating timestamps.

### 4. `app/schemas.py`
- **Module**: *Data Validation & Serialization Schema Module*
- **What it does**:
  1. Defines Pydantic data schemas for API request payloads and outgoing JSON responses.
  2. Validates user registration input, enforcing that passwords have at least 8 characters with a letter and a number.
  3. Sanitizes responses so internal data like password hashes and raw ciphertext are never leaked to users.

### 5. `app/security.py`
- **Module**: *Authentication & Password Security Module*
- **What it does**:
  1. Hashes user passwords using `bcrypt` with unique automatic salts, preventing dictionary and rainbow table attacks.
  2. Compares incoming login passwords against stored bcrypt hashes safely.
  3. Generates and decodes signed JSON Web Tokens (JWT) with cryptographic expiration timestamps using `python-jose`.

### 6. `app/crypto.py`
- **Module**: *Cryptographic Engine & Envelope Encryption Module*
- **What it does**:
  1. Generates an isolated 32-byte Data Encryption Key (DEK) for each individual uploaded file.
  2. Encrypts the file using Fernet authenticated encryption (AES-128-CBC + HMAC-SHA256) and wraps (encrypts) the DEK with the server's `MASTER_KEY`.
  3. Computes the SHA-256 integrity hash of the original plain file and provides the decryption function for Half 2.

### 7. `app/deps.py`
- **Module**: *Security Dependencies & Audit Logging Module*
- **What it does**:
  1. Implements `get_current_user`, inspecting incoming requests for a JWT token in either HTTP-only cookies or Authorization Bearer headers.
  2. Rejects requests with expired, altered, or missing credentials with HTTP 401 Unauthorized.
  3. Provides `log_security_event` to write tamper-evident audit records into the `transfer_logs` table for every critical action.

### 8. `app/routers/auth.py`
- **Module**: *User Authentication API Module*
- **What it does**:
  1. Exposes `/auth/register` to create new accounts, rejecting duplicate usernames or emails and hashing passwords.
  2. Exposes `/auth/login` to authenticate users, returning JWT tokens and setting browser `HttpOnly` cookies.
  3. Logs all authentication attempts (`REGISTER`, `LOGIN_SUCCESS`, `LOGIN_FAIL`) into the database for auditability.

### 9. `app/routers/files.py`
- **Module**: *Secure File Dispatch & Transfer API Module*
- **What it does**:
  1. Exposes `/files/upload` to validate receiver usernames, check file extensions against a whitelist, and verify file size limits.
  2. Calls `crypto.py` to encrypt the file in-memory and stores the ciphertext blob and wrapped key into PostgreSQL.
  3. Exposes `/files/sent` and `/files/received` to list file transmission metadata without revealing encrypted contents.

### 10. `app/routers/pages.py`
- **Module**: *Web Frontend & View Rendering Module*
- **What it does**:
  1. Renders HTML pages using Jinja2 templates for `/login`, `/register`, `/dashboard`, `/upload`, and `/logs`.
  2. Redirects unauthenticated users attempting to access protected pages to `/login`.
  3. Passes dynamic context data (user profile, sent files, received files, audit trail) to the templates.

### 11. `app/main.py`
- **Module**: *Application Bootstrap & Server Factory Module*
- **What it does**:
  1. Initializes the FastAPI web application and configures the startup lifespan.
  2. Auto-creates all PostgreSQL database tables at application launch using SQLAlchemy's `Base.metadata.create_all`.
  3. Mounts static files (CSS, JS), attaches all sub-routers, and provides the `/health` connectivity endpoint.

---

## How Encryption Works in this Project (The Lockbox Analogy)

To easily explain envelope encryption during your project viva or defense, use the **"Lockbox with Two Keys"** analogy:

```
+-----------------------------------------------------------------------------------------+
|                                THE LOCKBOX ANALOGY                                      |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|  1. THE DOCUMENT & CHECKSUM:                                                            |
|     You have an important document (the file). Before locking it away, you take a        |
|     digital fingerprint of it (the SHA-256 checksum) so you can prove later that no     |
|     words were altered.                                                                 |
|                                                                                         |
|  2. THE UNIQUE CHEAP PADLOCK (Per-File DEK):                                             |
|     Instead of using one master key to lock every document in the building, you grab a    |
|     brand-new, single-use padlock with its own unique key. You lock the document inside  |
|     a sturdy metal box (the ciphertext).                                                |
|                                                                                         |
|  3. THE MASTER BANK VAULT (Master Key Wrapping):                                         |
|     Now you have the small padlock key. To keep it safe, you take the server's heavy     |
|     Master Vault Key (MASTER_KEY in .env) and lock the small key inside a tamper-proof   |
|     capsule (the wrapped_key).                                                          |
|                                                                                         |
|  4. STORAGE IN POSTGRESQL:                                                              |
|     The locked metal box (encrypted BYTEA) and the capsule (wrapped_key) are placed on   |
|     the shelf in PostgreSQL. Even if an attacker steals the database, they only have a  |
|     locked box and an encrypted key capsule. Without the Master Key, they cannot open   |
|     the capsule, and without the small key, they cannot open the box!                   |
|                                                                                         |
|  5. DECRYPTION (Half 2):                                                                 |
|     When the authorized receiver wants the file, the server uses the Master Key to open |
|     the capsule, gets the small key, opens the box, checks the document's fingerprint   |
|     against the SHA-256 checksum, and hands the clean document to the recipient.        |
+-----------------------------------------------------------------------------------------+
```

### Why is this superior to basic encryption?
- **Key Isolation**: If one file's key is ever exposed, none of the other files are compromised.
- **Performance**: Large files are encrypted with fast symmetric keys (Fernet/AES), while the master key only ever encrypts tiny 32-byte key strings.
- **Defense in Depth**: The ciphertext and the key wrapper are stored separately from the master secret in `.env`.
