# Secure File Transfer System

A cybersecurity-focused web application designed and built for a B.Tech Major Project. This platform enables authenticated users to transmit sensitive files to designated recipients with **zero plain file exposure**. Every file is encrypted in-memory before being stored in PostgreSQL, and every security event is recorded in an immutable audit trail.

---

## Key Security Features

1. **Envelope Encryption (Data Encryption Key & Master Key Pattern)**:
   - For every uploaded file, an isolated, cryptographically secure 32-byte symmetric key (**Data Encryption Key / DEK**) is generated using `Fernet` (AES-128-CBC with HMAC-SHA256 authenticated encryption).
   - The file is encrypted strictly in-memory using this unique DEK.
   - The per-file DEK is wrapped (encrypted) with the server's `MASTER_KEY` (configured in `.env`) and stored in a separate column from the ciphertext.
   - The plaintext file is **never written to the server's filesystem or stored in the database**.

2. **End-to-End Integrity Verification (SHA-256)**:
   - A cryptographic SHA-256 checksum is computed from the original plaintext before encryption and saved in the database.
   - In Half 2, when the recipient downloads the file, the server computes the checksum of the decrypted bytes to guarantee non-repudiation and verify that no corruption or tampering took place.

3. **Strict Authentication & Access Control**:
   - Passwords are encrypted using **bcrypt** with salted hashing. Plain passwords are never persisted.
   - Authenticated sessions issue signed **JSON Web Tokens (JWT)** with 30-minute expiration.
   - Supports dual-mode authentication:
     - **HttpOnly, SameSite=Lax Cookies** for web browsers.
     - **`Authorization: Bearer <token>`** headers for REST API automation.
   - Mitigates user enumeration attacks by returning generic error messages (`"Invalid username or password"`) for all authentication failures.

4. **Comprehensive Security Audit Trail**:
   - The `transfer_logs` table logs every security event: `REGISTER`, `LOGIN_SUCCESS`, `LOGIN_FAIL`, and `UPLOAD`.
   - Records actor ID, transfer reference, success/failure status, and contextual notes.

---

## Technology Stack

- **Backend**: Python 3.11+, FastAPI
- **Database**: PostgreSQL with SQLAlchemy 2.0 ORM (`psycopg2-binary`)
- **Cryptography**: Python `cryptography` library (`Fernet` Envelope Encryption, SHA-256)
- **Password Security**: `bcrypt` (adaptive salted hashing)
- **Session & Tokens**: `python-jose` (HS256 JWT)
- **Data Validation**: Pydantic v2 & Pydantic-Settings
- **Frontend**: Jinja2 Templates + Tailwind CSS (via CDN)
- **Testing**: pytest & HTTPX

---

## Project Structure

```
secure-file-transfer/
├── app/
│   ├── __init__.py
│   ├── main.py              # Application factory, table initialization, /health endpoint
│   ├── config.py            # Loads configuration & secrets from .env
│   ├── database.py          # SQLAlchemy 2.0 engine, SessionLocal, get_db dependency
│   ├── models.py            # User, FileTransfer, TransferLog relational tables
│   ├── schemas.py           # Pydantic request/response validation schemas
│   ├── security.py          # Bcrypt password hashing & JWT token generation
│   ├── crypto.py            # Fernet envelope encryption, DEK generation, SHA-256
│   ├── deps.py              # JWT authentication dependency & audit logging helper
│   ├── routers/
│   │   ├── auth.py          # Authentication endpoints (/auth/register, /login, /logout, /me)
│   │   ├── files.py         # File endpoints (/files/upload, /files/sent, /files/received)
│   │   └── pages.py         # Jinja2 frontend routes (/, /login, /register, /dashboard, /upload, /logs)
│   ├── templates/           # Jinja2 HTML templates
│   │   ├── base.html        # Shared layout, navbar with shield icon, footer
│   │   ├── login.html       # Sign-in page with validation error handling
│   │   ├── register.html    # Account registration page
│   │   ├── dashboard.html   # Sent & Received files tables with disabled download button
│   │   ├── upload.html      # Drag-and-drop secure file dispatch interface
│   │   └── logs.html        # Security audit log table
│   └── static/
│       └── css/style.css    # Custom scrollbar & CSS styling
├── scripts/
│   └── show_encrypted.py   # CLI tool to inspect stored ciphertext (BYTEA)
├── tests/
│   ├── conftest.py          # SQLite in-memory test harness & TestClient
│   ├── test_auth.py         # TC-01: Auth, password hashing, and login tests
│   ├── test_crypto.py       # Envelope encryption, DEK uniqueness, tampering tests
│   └── test_upload.py       # TC-02: Secure upload, metadata, and validation tests
├── .env.example             # Template of environment variables
├── .env                     # Local active environment variables
├── requirements.txt         # Pinned project dependencies
├── EXPLAINED.md             # Codebase guide for viva & encryption analogy
└── README.md                # Project documentation
```

---

## Installation & Setup Guide

### 1. Prerequisites
Ensure you have installed:
- Python 3.11 or higher
- PostgreSQL (v14 or newer) running on `localhost:5432`

### 2. Clone / Open Directory
Open PowerShell or your terminal in the project directory:
```powershell
cd "c:\Users\shiva\OneDrive\Desktop\secure file transfer system\secure-file-transfer"
```

### 3. Create and Activate Virtual Environment
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 5. Configure `.env`
Ensure a `.env` file exists in the project root with the following parameters:
```env
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/secure_file_transfer
SECRET_KEY=b9f27c44243a819b16e83d8e57f00bb25b138865ceb11dc05d3b64c4fe8e7921
MASTER_KEY=o2m3T9G48V_z5FkR_oX7eH-5xGk_s0Q4G9zZ5qO6W7s=
ACCESS_TOKEN_EXPIRE_MINUTES=30
MAX_UPLOAD_MB=10
```

> **Tip to generate a new `MASTER_KEY`**:
> ```powershell
> python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
> ```

---

## Running the Application

### 1. Start the FastAPI Server
Run the application using `uvicorn`:
```powershell
.\.venv\Scripts\uvicorn app.main:app --reload --port 8000
```

At startup, SQLAlchemy automatically creates the database tables (`users`, `file_transfers`, `transfer_logs`) in PostgreSQL if they do not already exist.

### 2. Access the Application
- **Web Interface**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check Endpoint**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## Running the Test Suite

Execute the automated test suite with pytest:
```powershell
.\.venv\Scripts\pytest -v tests/
```

Test coverage includes:
- **TC-01 (`test_auth.py`)**: User registration, password complexity validation, rejection of duplicate usernames/emails, bcrypt hash verification (ensuring plain password is never saved), rejection of incorrect credentials, JWT and cookie verification, audit logging.
- **TC-02 (`test_upload.py`)**: File encryption before storage, verification that stored bytes differ from plain bytes, SHA-256 checksum persistence, rejection of self-transfers, rejection of empty files, rejection of oversized files (> 10 MB), rejection of disallowed file extensions (`.exe`, etc.), metadata endpoints.
- **`test_crypto.py`**: Per-file DEK uniqueness, envelope encryption & decryption, SHA-256 calculation, and rejection of tampered ciphertexts.

---

## Cybersecurity Demonstration Script

To prove to viva examiners that files in PostgreSQL are completely unreadable:
```powershell
.\.venv\Scripts\python scripts/show_encrypted.py <transfer_id>
```
Example:
```powershell
.\.venv\Scripts\python scripts/show_encrypted.py 1
```
This script queries the database record directly and displays:
1. The original filename and metadata.
2. The SHA-256 checksum.
3. The first 200 bytes of raw ciphertext (PostgreSQL `BYTEA`) formatted as a hex dump, demonstrating that stored data is encrypted and unintelligible.
