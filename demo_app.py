"""
demo_app.py — Intentionally vulnerable demo file for testing the CodeScan action.

DO NOT use any pattern here as a reference for real code.
This file exists only to trigger inline suggestion comments on a PR.

How to use
----------
1. Create a new branch in this repo.
2. git add this file and push.
3. Open a PR targeting main.
4. The CodeScan workflow will run and post inline suggestion comments
   on the Files changed tab — one per fixable line below.
"""

import hashlib
import os
import random
import requests
import ssl
import yaml

# ---------------------------------------------------------------------------
# rule: weak-crypto-md5  →  fix: hashlib.sha256()
# ---------------------------------------------------------------------------
def hash_user_id(user_id: str) -> str:
    return hashlib.md5(user_id.encode()).hexdigest()


# ---------------------------------------------------------------------------
# rule: weak-crypto-sha1  →  fix: hashlib.sha256()
# ---------------------------------------------------------------------------
def legacy_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


# ---------------------------------------------------------------------------
# rule: weak-random-for-security  →  fix: secrets.randbelow()
# ---------------------------------------------------------------------------
def generate_otp() -> str:
    return str(random.randint(100000, 999999))


def make_session_token() -> str:
    return str(random.randint(0, 999999999999999999999999999999))


# ---------------------------------------------------------------------------
# rule: tls-verify-disabled  →  fix: verify=True
# ---------------------------------------------------------------------------
def fetch_rates(currency: str):
    return requests.get(f"https://api.rates.example/{currency}", verify=False)


def push_report(payload: dict):
    return requests.post("https://reports.example/upload", json=payload, verify=False)


# ---------------------------------------------------------------------------
# rule: tls-context-check-hostname-disabled  →  fix: check_hostname = True
# ---------------------------------------------------------------------------
def legacy_ssl_context(ctx: ssl.SSLContext) -> ssl.SSLContext:
    ctx.check_hostname = False
    return ctx


# ---------------------------------------------------------------------------
# rule: insecure-yaml-load  →  fix: yaml.safe_load()
# ---------------------------------------------------------------------------
def load_config(raw: str) -> dict:
    return yaml.load(raw, Loader=yaml.UnsafeLoader)


# ---------------------------------------------------------------------------
# rule: debug-mode-enabled  →  fix: os.environ.get("DJANGO_DEBUG", "False") == "True"
# ---------------------------------------------------------------------------
DEBUG = True


# ---------------------------------------------------------------------------
# rule: cors-wildcard-origin  →  fix: explicit origin list
# ---------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = ["*"]


# ---------------------------------------------------------------------------
# rule: insecure-cookie-flags  →  fix: True
# ---------------------------------------------------------------------------
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False


# ---------------------------------------------------------------------------
# rule: empty-database-password  →  fix: os.environ.get("DB_PASSWORD", "")
# ---------------------------------------------------------------------------
DATABASE = {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": "app_prod",
    "USER": "postgres",
    "PASSWORD": "",
    "HOST": "10.0.1.5",
}
