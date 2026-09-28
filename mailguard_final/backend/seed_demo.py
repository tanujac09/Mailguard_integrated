"""
Quick demo helper: logs in and uploads the two sample .eml files in
sample_emails/ so you have something to look at on the dashboard
immediately after first setup.

Usage (with the backend already running on localhost:8000):
    python seed_demo.py <analyst_username> <analyst_password>
"""
import sys
import glob
import httpx

BASE = "http://localhost:8000"


def main():
    if len(sys.argv) != 3:
        print("Usage: python seed_demo.py <username> <password>")
        sys.exit(1)
    username, password = sys.argv[1], sys.argv[2]

    r = httpx.post(f"{BASE}/auth/login", data={"username": username, "password": password})
    r.raise_for_status()
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    for path in glob.glob("sample_emails/*.eml"):
        with open(path, "rb") as f:
            files = {"file": (path.split("/")[-1], f, "message/rfc822")}
            resp = httpx.post(f"{BASE}/emails/upload", headers=headers, files=files, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            print(f"Ingested {path}: score={data['fraud_score']} verdict={data['verdict']}")
        else:
            print(f"Failed to ingest {path}: {resp.status_code} {resp.text}")


if __name__ == "__main__":
    main()
