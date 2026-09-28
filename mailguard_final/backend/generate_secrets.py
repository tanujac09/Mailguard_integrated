"""
Run this once to generate the two values .env needs:
    python generate_secrets.py
"""
import secrets
import getpass
from passlib.hash import bcrypt

print("SECRET_KEY=" + secrets.token_hex(32))

pwd = getpass.getpass("Choose the analyst login password (input hidden): ")
print("ANALYST_PASSWORD_HASH=" + bcrypt.hash(pwd))
print("\nCopy both lines above into backend/.env")
