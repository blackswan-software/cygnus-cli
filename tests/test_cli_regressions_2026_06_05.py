"""Regression tests for the 2026-06-05 fresh-user-run findings.

Five user-facing bugs were filed against the published CLI:

  BUG 1  `cygnus --version` argparse-errors (no flag registered)
  BUG 2  `cygnus forgot-key` returns 'Forbidden' from server
         (CLI code is clean; investigation pointed at Cloudflare WAF —
          not pinnable in a CLI-side test, see TODO at bottom)
  BUG 3  `cygnus verify` in a C++ project says "No lockfile found"
         (cpp branch missing from _parse_lockfile)
  BUG 4  Documented "request verification" command doesn't exist;
         verify output at ATTESTATION_ONLY gave the user no next action
  BUG 5  `cygnus issue` crashes with NameError 'subprocess' not defined

These tests pin the fix shape for the four that ARE testable. Run with:

  pytest tests/test_cli_regressions_2026_06_05.py -v
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Run the CLI directly from source so tests work without a pip install.
REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_ENV = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}


def _run_cli(*args, cwd=None):
    """Invoke `python -m cygnus.cli <args>` with the source-tree on PYTHONPATH."""
    return subprocess.run(
        [sys.executable, "-m", "cygnus.cli", *args],
        capture_output=True, text=True, timeout=30,
        cwd=cwd or REPO_ROOT, env=CLI_ENV,
    )


# ── BUG 1 — cygnus --version ──────────────────────────────────────────────

class TestVersionFlag:
    def test_version_flag_returns_version_string(self):
        r = _run_cli("--version")
        assert r.returncode == 0, (
            f"`cygnus --version` exited {r.returncode}\nstderr: {r.stderr}"
        )
        assert "cygnus" in r.stdout.lower(), (
            f"`cygnus --version` output didn't contain 'cygnus': {r.stdout!r}"
        )

    def test_short_form_V_flag_works(self):
        r = _run_cli("-V")
        assert r.returncode == 0
        assert "cygnus" in r.stdout.lower()


# ── BUG 3 — project-wide C++ scan ─────────────────────────────────────────

class TestCppProjectScan:
    """The _parse_lockfile function must handle cpp; previously the branch
    was missing entirely so any cpp project reported 'No lockfile found'."""

    def test_conanfile_txt_parses(self, tmp_path):
        (tmp_path / "conanfile.txt").write_text(
            "[requires]\nspdlog/1.17.0\nfmt/10.0.0\n\n[generators]\nCMakeDeps\n"
        )
        r = _run_cli("--ecosystem", "cpp", "verify", cwd=str(tmp_path))
        # Should NOT say "no lockfile found"; should at least list the libs.
        out = r.stdout + r.stderr
        assert "No lockfile found" not in out, (
            "cpp project with conanfile.txt still reports 'No lockfile "
            f"found' — _parse_lockfile cpp branch regressed.\n{out}"
        )
        assert "spdlog" in out or "fmt" in out, (
            f"Expected spdlog/fmt in output; got:\n{out}"
        )

    def test_vcpkg_json_parses(self, tmp_path):
        (tmp_path / "vcpkg.json").write_text(json.dumps({
            "name": "myapp",
            "version-string": "0.1.0",
            "dependencies": ["spdlog", {"name": "fmt", "version>=": "9.0"}],
        }))
        r = _run_cli("--ecosystem", "cpp", "verify", cwd=str(tmp_path))
        out = r.stdout + r.stderr
        assert "No lockfile found" not in out
        assert "spdlog" in out or "fmt" in out

    def test_cmakelists_find_package_parses(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.20)\n'
            'project(myapp CXX)\n'
            'find_package(spdlog REQUIRED)\n'
            'find_package(fmt CONFIG REQUIRED)\n'
        )
        r = _run_cli("--ecosystem", "cpp", "verify", cwd=str(tmp_path))
        out = r.stdout + r.stderr
        assert "No lockfile found" not in out


# ── BUG 4 — `cygnus request` exists + verify hint surfaces ────────────────

class TestRequestCommand:
    def test_request_command_registered(self):
        r = _run_cli("request", "--help")
        assert r.returncode == 0, (
            f"`cygnus request --help` failed — command not registered\n"
            f"stderr: {r.stderr}"
        )
        assert "library" in r.stdout.lower()

    def test_top_level_help_lists_request(self):
        r = _run_cli("--help")
        assert "request" in r.stdout, (
            "top-level `cygnus --help` does not list the `request` "
            "subcommand"
        )

    def test_request_takes_optional_version(self):
        # Argparse should accept `cygnus request spdlog` AND
        # `cygnus request spdlog 1.17.0` — version is optional.
        r = _run_cli("request", "--help")
        assert "version" in r.stdout.lower()


# ── BUG 5 — `cygnus issue` no NameError ───────────────────────────────────

class TestCygnusIssueNoCrash:
    """The fallback path (when gh CLI isn't installed) used to crash with
    NameError because `subprocess` wasn't imported inside cmd_issue."""

    def test_issue_with_body_does_not_crash(self):
        # --body skips the $EDITOR path, going straight to the
        # `subprocess.run(["gh", "issue", ...])` block that crashed.
        # The `gh` CLI almost certainly isn't on the test runner, so the
        # fallback URL-print path should fire. Either way, NO NameError.
        r = _run_cli("issue", "smoke-title", "--body", "smoke-body")
        full = r.stdout + r.stderr
        assert "NameError" not in full, (
            f"`cygnus issue` regressed with NameError:\n{full}"
        )
        assert "name 'subprocess' is not defined" not in full

    def test_issue_with_empty_editor_does_not_crash(self, tmp_path):
        # When --body is missing, the editor block fires. Force EDITOR=true
        # so it exits cleanly without spawning anything interactive.
        env = {**CLI_ENV, "EDITOR": "true"}
        r = subprocess.run(
            [sys.executable, "-m", "cygnus.cli", "issue", "smoke"],
            capture_output=True, text=True, timeout=30,
            env=env, cwd=REPO_ROOT,
            input="\n",  # accept empty body
        )
        full = r.stdout + r.stderr
        assert "NameError" not in full


# ── BUG 2 — forgot-key 403 ────────────────────────────────────────────────

class TestForgotKey403:
    """The user-facing fix for BUG 2 is twofold:

      (A) live integration — the production /auth/forgot-key endpoint
          must not return 403 for a properly-formed POST. If CI ever
          hits 403, something on the wire (Cloudflare WAF, proxy, IP
          deny-list) regressed and we want loud failure here.

      (B) graceful handling — when the CLI DOES see 403, the user
          must get an actionable next step (email support@), not a
          dead-end one-word "Error: Forbidden".

    A previous version of this file marked the test @pytest.mark.skip
    which is the opposite of fixing — it hid the bug instead of pinning
    a behavior. Removed 2026-06-05.
    """

    def test_live_endpoint_does_not_return_403(self):
        """Hit the production /auth/forgot-key with a smoke email; assert
        the response is not 403. Skipped only when the CLI environment
        can't reach the public registry (offline CI runner). On a
        normally-reachable CI runner this is the live regression alarm."""
        import urllib.request
        import urllib.error

        # Use the same URL the CLI uses.
        from cygnus.cli import REGISTRY_URL
        url = f"{REGISTRY_URL}/auth/forgot-key"
        payload = json.dumps({"email": "ci-smoke-test@example.invalid"}).encode()
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "cygnus-cli/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        except urllib.error.URLError as e:
            pytest.skip(f"registry unreachable from CI runner: {e}")
            return

        assert status != 403, (
            f"/auth/forgot-key returned 403 from the CLI's standard POST. "
            f"This is the 'dead-end Forbidden' the fresh-user run hit. "
            f"Investigate Cloudflare WAF / proxy / IP deny-list on the "
            f"path. Expected: 200 (generic success) or 429 (rate limit)."
        )

    def test_cli_handles_403_gracefully_not_dead_end(self):
        """When /auth/forgot-key returns 403, the CLI must print:
          · the support@ email
          · a description of why (WAF / rate / deny-list)
        and NOT just one-word 'Forbidden'. Tested by intercepting at the
        urllib layer so this works offline."""
        import urllib.error
        from io import BytesIO

        def fake_urlopen(req, timeout=None):
            # Simulate the WAF returning 403 with a generic body.
            raise urllib.error.HTTPError(
                req.full_url, 403, "Forbidden",
                {}, BytesIO(b'{"detail":"Forbidden"}'),
            )

        # Use python -c to actually invoke cmd_auth_forgot_key, since the
        # error path calls sys.exit which would also exit pytest.
        script = (
            "import sys; sys.path.insert(0, %r);\n"
            "import urllib.request, urllib.error;\n"
            "from io import BytesIO;\n"
            "def fake_urlopen(req, timeout=None):\n"
            "    raise urllib.error.HTTPError(req.full_url, 403, 'Forbidden', {}, BytesIO(b'{}'))\n"
            "urllib.request.urlopen = fake_urlopen;\n"
            "from cygnus.cli import cmd_auth_forgot_key;\n"
            "import argparse; ns = argparse.Namespace(email='x@y.test');\n"
            "try:\n"
            "    cmd_auth_forgot_key(ns)\n"
            "except SystemExit:\n"
            "    pass\n"
        ) % str(REPO_ROOT)
        r = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15, env=CLI_ENV,
        )
        full = r.stdout + r.stderr
        assert "support@blackswan-software.ai" in full, (
            f"On 403, CLI must offer the support@ recovery path but "
            f"output didn't mention it.\n{full}"
        )
        assert full.strip().lower() != "error: forbidden", (
            f"On 403, CLI fell back to the dead-end one-word error.\n{full}"
        )
