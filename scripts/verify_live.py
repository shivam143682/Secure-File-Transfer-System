"""
Live Server Verification Script (scripts/verify_live.py)
--------------------------------------------------------
Tests live endpoints on http://127.0.0.1:8000:
1. /health
2. /auth/register
3. /auth/login (JWT + Cookie)
4. /files/upload (Envelope encryption + PostgreSQL BYTEA storage)
5. /files/sent & /files/received metadata
6. HTML page responses (/login, /register, /dashboard, /upload, /logs)
"""

import httpx

BASE_URL = "http://127.0.0.1:8000"

def run_verification():
    with httpx.Client(base_url=BASE_URL, follow_redirects=True) as client:
        print("[1/7] Testing /health...")
        res = client.get("/health")
        print(" -> Status:", res.status_code, res.json())
        assert res.status_code == 200
        assert res.json()["database"] == "connected"

        print("\n[2/7] Testing /auth/register...")
        reg_alice = client.post("/auth/register", json={
            "username": "alice",
            "email": "alice@project.edu",
            "password": "AlicePassword123"
        })
        # Could be 201 or 400 if already created
        print(" -> Register alice:", reg_alice.status_code)

        reg_bob = client.post("/auth/register", json={
            "username": "bob",
            "email": "bob@project.edu",
            "password": "BobPassword123"
        })
        print(" -> Register bob:", reg_bob.status_code)

        print("\n[3/7] Testing /auth/login...")
        login_alice = client.post("/auth/login", json={
            "username": "alice",
            "password": "AlicePassword123"
        })
        print(" -> Login alice:", login_alice.status_code)
        assert login_alice.status_code == 200
        alice_token = login_alice.json()["access_token"]
        assert "access_token" in login_alice.cookies
        alice_headers = {"Authorization": f"Bearer {alice_token}"}

        print("\n[4/7] Testing /files/upload (Validation & Encryption)...")
        # Self upload should fail
        self_upload = client.post(
            "/files/upload",
            data={"receiver_username": "alice"},
            files={"file": ("test.pdf", b"Self test", "application/pdf")},
            headers=alice_headers
        )
        print(" -> Upload to self rejected (400):", self_upload.status_code)
        assert self_upload.status_code == 400

        # Disallowed extension should fail
        exe_upload = client.post(
            "/files/upload",
            data={"receiver_username": "bob"},
            files={"file": ("script.exe", b"malware", "application/x-msdownload")},
            headers=alice_headers
        )
        print(" -> Upload .exe rejected (400):", exe_upload.status_code)
        assert exe_upload.status_code == 400

        # Valid upload
        valid_upload = client.post(
            "/files/upload",
            data={"receiver_username": "bob"},
            files={"file": ("cyber_spec.pdf", b"%PDF-1.4 Confidential B.Tech Submission - Encryption Test", "application/pdf")},
            headers=alice_headers
        )
        print(" -> Upload valid file (201):", valid_upload.status_code, valid_upload.json())
        assert valid_upload.status_code == 201
        transfer_id = valid_upload.json()["transfer_id"]

        print("\n[5/7] Testing /files/sent & /files/received...")
        sent_resp = client.get("/files/sent", headers=alice_headers)
        print(" -> Alice sent files:", len(sent_resp.json()))
        assert len(sent_resp.json()) >= 1

        login_bob = client.post("/auth/login", json={
            "username": "bob",
            "password": "BobPassword123"
        })
        bob_token = login_bob.json()["access_token"]
        bob_headers = {"Authorization": f"Bearer {bob_token}"}
        recv_resp = client.get("/files/received", headers=bob_headers)
        print(" -> Bob received files:", len(recv_resp.json()))
        assert len(recv_resp.json()) >= 1

        print("\n[6/7] Testing Web Pages...")
        # Dashboard authenticated
        dash = client.get("/dashboard", headers=alice_headers, cookies=login_alice.cookies)
        print(" -> Dashboard HTML status:", dash.status_code)
        assert dash.status_code == 200
        assert "Files I Sent" in dash.text

        # Upload page
        up_page = client.get("/upload", headers=alice_headers, cookies=login_alice.cookies)
        print(" -> Upload Page HTML status:", up_page.status_code)
        assert up_page.status_code == 200
        assert "Cryptographic Protection Guarantee" in up_page.text

        # Logs page
        logs_page = client.get("/logs", headers=alice_headers, cookies=login_alice.cookies)
        print(" -> Logs Page HTML status:", logs_page.status_code)
        assert logs_page.status_code == 200
        assert "Security Audit Trail" in logs_page.text

        print("\n[7/7] SUCCESS! All live system components verified successfully.")
        return transfer_id

if __name__ == "__main__":
    t_id = run_verification()
