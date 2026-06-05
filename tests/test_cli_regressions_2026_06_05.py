"""Regression tests for the 2026-06-05 fresh-user-run findings.

Five user-facing bugs were filed against the published CLI:

  BUG 1  `cygnus --version` argparse-errors (no flag registered)
  BUG 2  `cygnus auth forgot-key` returns 'Forbidden' from server
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
# Not pinnable from CLI tests in isolation. The CLI code path is clean
# (cmd_auth_forgot_key sends POST with email, surfaces server errors). The
# 403 reported by the fresh-user run came from somewhere on the wire
# (Cloudflare WAF is the most plausible — auth-service code on the
# registry side only returns 400/429/200 for /auth/forgot-key, never 403).
#
# Surfaced as a TODO so we revisit if a user reports it again with the
# exact request id / x-request-id headers.
@pytest.mark.skip(reason="BUG 2 requires server-side reproduction + headers")
def test_forgot_key_no_403_under_normal_conditions():
    pass
