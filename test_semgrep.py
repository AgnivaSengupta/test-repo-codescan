"""
test_semgrep_runner.py — Verifies that Semgrep is installed and reachable,
and that the semantics_checker integration routes findings back correctly.

Run with:
    pytest tests/test_semgrep_runner.py -v

Test layers
-----------
1. smoke_test_semgrep_installed   – semgrep --version exits 0 (binary on PATH)
2. test_semgrep_json_output       – raw `semgrep --json` round-trips valid JSON
3. test_semantics_checker_weak_crypto  – checker finds MD5/SHA-1 via rules/
4. test_semantics_checker_tls_issues   – checker finds verify=False via rules/
5. test_semantics_checker_injection    – checker finds shell=True via rules/
6. test_semantics_checker_clean_repo   – checker returns zero findings for safe code
7. test_semgrep_not_found_graceful     – FileNotFoundError returns a safe error dict
"""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from engine.codescan.semantics_checker import _run_semgrep, run_semantics_checker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(root: Path, rel: str, content: str) -> Path:
    """Write root/rel, creating parents as needed. Dedents content."""
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(content), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# 1. Smoke test — is semgrep on PATH?
# ---------------------------------------------------------------------------

def test_semgrep_installed():
    """
    Fails immediately with a clear message if `semgrep` is not installed.
    All subsequent tests depend on this.
    """
    binary = shutil.which("semgrep")
    assert binary is not None, (
        "semgrep binary not found on PATH.\n"
        "Install it with:  pip install semgrep\n"
        "Then re-run:      pytest tests/test_semgrep_runner.py -v"
    )


def test_semgrep_version():
    """semgrep --version must exit cleanly (exit code 0)."""
    result = subprocess.run(
        ["semgrep", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"semgrep --version exited {result.returncode}.\n"
        f"stderr: {result.stderr}"
    )
    # Version string should be non-empty
    version_output = (result.stdout + result.stderr).strip()
    assert version_output, "semgrep --version produced no output"
    print(f"\n[semgrep version] {version_output}")


# ---------------------------------------------------------------------------
# 2. Raw JSON output sanity check
# ---------------------------------------------------------------------------

def test_semgrep_json_output(tmp_path: Path):
    """
    Calls semgrep directly (not through our wrapper) with --json on a tiny
    Python snippet to confirm the CLI produces parseable JSON output.
    """
    # Write a minimal vulnerable snippet
    target = _write(
        tmp_path,
        "vuln.py",
        """\
        import hashlib
        def checksum(data):
            return hashlib.md5(data).hexdigest()
        """,
    )

    rules_dir = Path(__file__).parent.parent / "engine" / "codescan" / "rules"
    cmd = [
        "semgrep",
        "--config", str(rules_dir),
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--disable-version-check",
        "--metrics", "off",
        str(target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

    assert proc.returncode in (0, 1), (
        f"semgrep exited with unexpected code {proc.returncode}.\n"
        f"stderr: {proc.stderr}"
    )

    stdout = proc.stdout.strip()
    assert stdout, (
        "semgrep produced no stdout.\n"
        f"stderr: {proc.stderr}"
    )

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(f"semgrep output is not valid JSON: {exc}\nstdout: {stdout[:500]}")

    assert "results" in parsed, f"JSON output missing 'results' key: {parsed.keys()}"
    assert "errors" in parsed,  f"JSON output missing 'errors' key:  {parsed.keys()}"


# ---------------------------------------------------------------------------
# 3-6. semantics_checker integration tests (use our wrapper + real rules)
# ---------------------------------------------------------------------------

class TestSemanticsCheckerIntegration:
    """
    Uses run_semantics_checker() end-to-end with the project's real Semgrep
    rules in engine/codescan/rules/.
    Skips automatically when semgrep is not installed.
    """

    @pytest.fixture(autouse=True)
    def skip_if_no_semgrep(self):
        if shutil.which("semgrep") is None:
            pytest.skip("semgrep not installed — skipping integration tests")

    # ------------------------------------------------------------------ #
    # 3. Weak crypto
    # ------------------------------------------------------------------ #
    def test_finds_weak_crypto(self, tmp_path: Path):
        """MD5 and SHA-1 usage should produce WEAK_CRYPTO findings."""
        _write(
            tmp_path,
            "crypto.py",
            """\
            import hashlib

            def bad_checksum(data: bytes) -> str:
                return hashlib.md5(data).hexdigest()

            def also_bad(data: bytes) -> str:
                return hashlib.sha1(data).hexdigest()
            """,
        )
        rel_path = "crypto.py"
        result = run_semantics_checker(str(tmp_path), [rel_path])

        rule_ids = [f.rule_id for f in result.findings]
        assert result.findings, (
            "Expected at least one weak-crypto finding but got none.\n"
            f"errors: {result.errors}"
        )
        # At least one finding should reference MD5 or SHA1 in its rule ID
        crypto_hits = [
            f for f in result.findings
            if any(kw in f.rule_id.lower() for kw in ("md5", "sha1", "sha-1", "weak", "crypto"))
        ]
        assert crypto_hits, (
            f"No weak-crypto rule fired. Rule IDs returned: {rule_ids}"
        )

    # ------------------------------------------------------------------ #
    # 4. TLS issues
    # ------------------------------------------------------------------ #
    def test_finds_tls_verify_false(self, tmp_path: Path):
        """requests.get(url, verify=False) should produce a TLS finding."""
        _write(
            tmp_path,
            "client.py",
            """\
            import requests

            def fetch(url):
                return requests.get(url, verify=False)
            """,
        )
        result = run_semantics_checker(str(tmp_path), ["client.py"])

        assert result.findings, (
            "Expected at least one TLS finding but got none.\n"
            f"errors: {result.errors}"
        )
        tls_hits = [
            f for f in result.findings
            if any(kw in f.rule_id.lower() for kw in ("tls", "verify", "ssl", "cert"))
        ]
        assert tls_hits, (
            "Expected a TLS/verify rule to fire. "
            f"Rule IDs returned: {[f.rule_id for f in result.findings]}"
        )

    # ------------------------------------------------------------------ #
    # 5. Injection
    # ------------------------------------------------------------------ #
    def test_finds_shell_injection(self, tmp_path: Path):
        """subprocess.run(cmd, shell=True) should produce an injection finding."""
        _write(
            tmp_path,
            "runner.py",
            """\
            import subprocess

            def run_cmd(user_input):
                subprocess.run(user_input, shell=True)
            """,
        )
        result = run_semantics_checker(str(tmp_path), ["runner.py"])

        assert result.findings, (
            "Expected at least one injection finding but got none.\n"
            f"errors: {result.errors}"
        )
        injection_hits = [
            f for f in result.findings
            if any(kw in f.rule_id.lower() for kw in ("inject", "shell", "command", "exec"))
        ]
        assert injection_hits, (
            "Expected a shell-injection rule to fire. "
            f"Rule IDs returned: {[f.rule_id for f in result.findings]}"
        )

    # ------------------------------------------------------------------ #
    # 6. Clean repo — no false positives
    # ------------------------------------------------------------------ #
    def test_clean_repo_no_findings(self, tmp_path: Path):
        """Safe code should produce zero semgrep findings."""
        _write(
            tmp_path,
            "safe.py",
            """\
            import hashlib
            import secrets

            def good_checksum(data: bytes) -> str:
                return hashlib.sha256(data).hexdigest()

            def generate_token() -> str:
                return secrets.token_hex(32)
            """,
        )
        result = run_semantics_checker(str(tmp_path), ["safe.py"])

        semgrep_findings = [
            f for f in result.findings
            if f.source_engine == "semgrep"
        ]
        assert semgrep_findings == [], (
            f"Got unexpected findings on clean code: "
            f"{[(f.rule_id, f.message) for f in semgrep_findings]}"
        )


# ---------------------------------------------------------------------------
# 7. Unit test — _run_semgrep graceful failure when binary missing
# ---------------------------------------------------------------------------

class TestRunSemgrepUnit:
    """
    Patches subprocess.run so these tests work even without semgrep installed.
    """

    def test_file_not_found_returns_error_dict(self, tmp_path: Path):
        """
        If semgrep is not on PATH, _run_semgrep must return a structured
        error dict instead of raising FileNotFoundError.
        """
        with patch("engine.codescan.semantics_checker.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("semgrep not found")
            result = _run_semgrep(["dummy.py"], str(tmp_path))

        assert result["results"] == []
        assert result["errors"], "Expected at least one error entry"
        assert any(
            "not found" in (err.get("message") or "").lower()
            for err in result["errors"]
        ), f"Unexpected error messages: {result['errors']}"

    def test_timeout_returns_error_dict(self, tmp_path: Path):
        """
        If semgrep times out, _run_semgrep must return a structured error
        dict instead of propagating subprocess.TimeoutExpired.
        """
        with patch("engine.codescan.semantics_checker.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=300)
            result = _run_semgrep(["dummy.py"], str(tmp_path))

        assert result["results"] == []
        assert any(
            "timed out" in (err.get("message") or "").lower()
            for err in result["errors"]
        ), f"Expected timeout message, got: {result['errors']}"

    def test_invalid_json_returns_error_dict(self, tmp_path: Path):
        """
        If semgrep emits non-JSON stdout, _run_semgrep must handle the
        JSONDecodeError and return an error dict.
        """
        mock_proc = MagicMock()
        mock_proc.stdout = "this is not json {{{{{"
        mock_proc.stderr = ""
        mock_proc.returncode = 0

        with patch("engine.codescan.semantics_checker.subprocess.run", return_value=mock_proc):
            result = _run_semgrep(["dummy.py"], str(tmp_path))

        assert result["results"] == []
        assert any(
            "parse" in (err.get("message") or "").lower()
            for err in result["errors"]
        ), f"Expected parse-error message, got: {result['errors']}"

    def test_empty_stdout_returns_error_dict(self, tmp_path: Path):
        """
        If semgrep exits but writes nothing to stdout, _run_semgrep must
        return a structured error dict rather than crashing on json.loads('').
        """
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = "some internal semgrep error"
        mock_proc.returncode = 2

        with patch("engine.codescan.semantics_checker.subprocess.run", return_value=mock_proc):
            result = _run_semgrep(["dummy.py"], str(tmp_path))

        assert result["results"] == []
        assert result["errors"], "Expected error list to be non-empty"
