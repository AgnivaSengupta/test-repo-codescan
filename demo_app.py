"""
demo_app.py — Intentionally vulnerable demo file for testing the CodeScan action.

DO NOT use any pattern here as a reference for real code.
This file exists only to trigger inline suggestion comments on a PR.
"""

import hashlib
import os
import random
import requests
import sqlite3
import ssl
import subprocess
import yaml

# ---------------------------------------------------------------------------
# rule: hardcoded-secret (Entropy Scanner)
# ---------------------------------------------------------------------------
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "super_secret_production_password_123!"

# ---------------------------------------------------------------------------
# rule: weak-crypto-md5 / weak-crypto-sha1
# ---------------------------------------------------------------------------
def hash_user_id(user_id: str) -> str:
    return hashlib.md5(user_id.encode()).hexdigest()

def legacy_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

# ---------------------------------------------------------------------------
# rule: weak-random-for-security
# ---------------------------------------------------------------------------
def generate_otp() -> str:
    return str(random.randint(100000, 999999))

# ---------------------------------------------------------------------------
# rule: tls-verify-disabled
# ---------------------------------------------------------------------------
def push_report(payload: dict):
    # This will trigger a finding because verify=False
    return requests.post("https://reports.example/upload", json=payload, verify=False)

# ---------------------------------------------------------------------------
# rule: tls-context-check-hostname-disabled
# ---------------------------------------------------------------------------
def legacy_ssl_context(ctx: ssl.SSLContext) -> ssl.SSLContext:
    ctx.check_hostname = False
    return ctx

# ---------------------------------------------------------------------------
# rule: command-injection-os-system
# ---------------------------------------------------------------------------
def ping_server(ip_address: str):
    # DANGEROUS: Untrusted input passed directly to the shell
    os.system(f"ping -c 4 {ip_address}")

def run_backup(backup_name: str):
    # DANGEROUS: shell=True with dynamic input
    subprocess.run(f"tar -czvf {backup_name}.tar.gz /data", shell=True)

# ---------------------------------------------------------------------------
# rule: sql-injection-fstring
# ---------------------------------------------------------------------------
def get_user_by_name(username: str):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # DANGEROUS: F-string interpolation directly into SQL query
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()

# ---------------------------------------------------------------------------
# rule: unsafe-yaml-load
# ---------------------------------------------------------------------------
def parse_user_config(yaml_string: str):
    # DANGEROUS: Uses the unsafe yaml.Loader which can execute arbitrary code
    return yaml.load(yaml_string, Loader=yaml.Loader)
