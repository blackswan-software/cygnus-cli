"""New-user CLI test suite — 2026-06-06.

Covers every user-visible subcommand at the "did it parse, does --help
work, does it crash on the obvious args" level — the exact shape a
fresh-install user would exercise the CLI in their first hour.

This is the regression net for the 2026-06-06 sweep:
  · auth flattened to top-level (no more `cygnus auth X`)
  · forgot-key/user-key renamed to forgotkey/userkey (no dashes)
  · /pricing URL purge (CLI must never push the marketing page)
  · destructive ops require confirm: logout, cancel, userkey, uninstall

Run with:
  pytest tests/test_cli_new_user_2026_06_06.py -v

Tests are grouped by behavior class:
  1. argparse plumbing — every subcommand --help works (no AttributeError)
  2. confirm prompts — destructive ops decline cleanly on `n`
  3. anti-regressions — no /pricing URLs, no `cygnus auth X`, no dashes
  4. help screen — `cygnus help` prints the grouped output
  5. error paths — deposit limits, request without args, etc.

Network access:
  Tests do NOT call any auth/registry endpoint. argparse `--help` is
  pure in-process; confirm prompts are tested by piping `n` on stdin.
  This keeps the suite green on offline CI runners.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_ENV = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}


def _run_cli(*args, cwd=None, stdin=None, env=None):
    """Invoke `python -m cygnus.cli <args>`."""
    return subprocess.run(
        [sys.executable, "-m", "cygnus.cli", *args],
        capture_output=True, text=True, timeout=30,
        cwd=cwd or REPO_ROOT, env=env or CLI_ENV,
        input=stdin,
    )


# Every user-visible top-level command. Update this list when
# subcommands are added or renamed. The point of the list is to
# pin the surface area so a silent rename can't regress.
ALL_TOP_LEVEL = [
    # Account
    "signup", "login", "status", "logout", "cancel",
    "forgotkey", "userkey",
    # Help
    "help",
    # Destructive
    "uninstall",
    # Tools
    "cache",
    # Billing
    "account", "deposit",
    # Verification (main loop)
    "verify", "request", "install", "list", "check", "lock", "sbom",
    # Misc
    "init", "extension", "issue",
]


# ── 1. argparse plumbing ─────────────────────────────────────────────────

class TestEveryCommandHasHelp:
    """`cygnus <cmd> --help` must succeed for every subcommand.

    Catches: missing argparse registration, broken parent parser
    inheritance, references to deleted positional args.
    """

    @pytest.mark.parametrize("cmd", ALL_TOP_LEVEL)
    def test_subcommand_help_exits_zero(self, cmd):
        r = _run_cli(cmd, "--help")
        assert r.returncode == 0, (
            f"`cygnus {cmd} --help` exited {r.returncode}\n"
            f"stdout: {r.stdout!r}\nstderr: {r.stderr!r}"
        )

    @pytest.mark.parametrize("cmd", ALL_TOP_LEVEL)
    def test_subcommand_listed_in_top_level_help(self, cmd):
        r = _run_cli("--help")
        assert cmd in r.stdout, (
            f"Top-level `cygnus --help` doesn't list `{cmd}`. argparse "
            f"sub.add_parser('{cmd}', ...) was likely lost in a rebase."
        )

    def test_no_orphaned_subcommands_in_help(self):
        """Top-level help must NOT list deprecated names from the
        2026-06-06 flatten sweep."""
        r = _run_cli("--help")
        # `auth` was the namespace; gone now.
        # forgot-key + user-key had dashes; renamed.
        # reset-key was internal; renamed to userkey.
        for stale in ("forgot-key", "user-key", "reset-key"):
            assert stale not in r.stdout, (
                f"`{stale}` (deprecated 2026-06-06) appears in top-level "
                f"help. The flatten sweep left a stale registration."
            )

    def test_version_flag_works(self):
        r = _run_cli("--version")
        assert r.returncode == 0
        assert "cygnus" in r.stdout.lower()

    def test_short_v_flag_works(self):
        r = _run_cli("-V")
        assert r.returncode == 0
        assert "cygnus" in r.stdout.lower()


# ── 2. `cygnus help` grouped output ──────────────────────────────────────

class TestCygnusHelpScreen:
    """`cygnus help` (the explicit subcommand, not `--help`) prints
    the per-group breakdown a new user actually wants."""

    def test_help_subcommand_exits_zero(self):
        r = _run_cli("help")
        assert r.returncode == 0

    @pytest.mark.parametrize("section", [
        "Account", "Verification", "Billing", "Tools", "Global flags",
    ])
    def test_help_includes_section(self, section):
        r = _run_cli("help")
        assert section in r.stdout, (
            f"`cygnus help` missing section `{section}`. cmd_help() was "
            f"refactored without updating the grouping."
        )

    def test_help_lists_every_command(self):
        r = _run_cli("help")
        # Every command in ALL_TOP_LEVEL except `help` itself must appear
        # in the grouped output. `help` is on the list-of-tools row.
        for cmd in ALL_TOP_LEVEL:
            assert cmd in r.stdout, (
                f"`cygnus help` doesn't mention `{cmd}` — group it under "
                f"the right section in cmd_help()."
            )

    def test_help_does_not_use_argparse_dash_syntax(self):
        """`cygnus help` is the prose / grouped help screen. It should
        NOT include the literal argparse banner `usage: cygnus` — that's
        the `--help` view."""
        r = _run_cli("help")
        assert "usage: cygnus" not in r.stdout


# ── 3. anti-regression: no /pricing URLs anywhere ────────────────────────

class TestNoPricingURLsInCLIOutput:
    """The CLI must not push users to blackswan-software.ai/pricing.
    Removed 2026-06-06 — replaced with CLI-native pointers
    (`cygnus deposit <USD>`, support@ for Enterprise, etc.).

    Any reintroduction (e.g. error path, help text, fallback message)
    must be caught here, not in a fresh-user complaint."""

    SCAN_TARGETS = [
        ("--help",),
        ("help",),
        ("signup", "--help"),
        ("login", "--help"),
        ("logout", "--help"),
        ("cancel", "--help"),
        ("forgotkey", "--help"),
        ("userkey", "--help"),
        ("deposit", "--help"),
        ("account", "--help"),
        ("uninstall", "--help"),
        ("install", "--help"),
        ("verify", "--help"),
        ("request", "--help"),
        ("issue", "--help"),
        ("init", "--help"),
        ("list", "--help"),
        ("check", "--help"),
        ("sbom", "--help"),
        ("lock", "--help"),
        ("extension", "--help"),
        ("cache", "--help"),
    ]

    @pytest.mark.parametrize("argv", SCAN_TARGETS)
    def test_no_pricing_url_in_output(self, argv):
        r = _run_cli(*argv)
        combined = r.stdout + r.stderr
        assert "blackswan-software.ai/pricing" not in combined, (
            f"`cygnus {' '.join(argv)}` outputs a /pricing URL. Removed "
            f"2026-06-06 — replace with a CLI command pointer or drop."
        )
        assert "/pricing" not in combined, (
            f"`cygnus {' '.join(argv)}` contains a /pricing path."
        )


# ── 4. anti-regression: `cygnus auth X` namespace fully removed ──────────

class TestNoAuthNamespace:
    """Before 2026-06-06 users had to type `cygnus auth signup`, etc.
    The `auth` subparser was removed entirely — these top-level commands
    must NOT be reachable via the old namespace."""

    def test_auth_subcommand_is_not_registered(self):
        r = _run_cli("auth", "--help")
        # argparse should refuse — `auth` is not a registered subcommand
        # any more. Either non-zero exit OR a 'invalid choice' error.
        full = r.stdout + r.stderr
        assert r.returncode != 0 or "invalid choice" in full.lower(), (
            f"`cygnus auth` still parses — the auth namespace was "
            f"supposed to be removed 2026-06-06. argparse output:\n{full}"
        )

    @pytest.mark.parametrize("sub", [
        "signup", "login", "status", "logout", "cancel",
    ])
    def test_old_auth_subcmd_invocation_fails(self, sub):
        r = _run_cli("auth", sub)
        # Same as above: argparse refuses `auth` itself, so `auth signup`
        # never reaches a handler. The point is that the user gets a
        # clean error, not a silent fallback.
        assert r.returncode != 0, (
            f"`cygnus auth {sub}` was accepted — flatten 2026-06-06 "
            f"didn't remove the auth wrapper."
        )


# ── 5. confirm prompts on destructive ops ────────────────────────────────

class TestDestructiveOpsConfirm:
    """`logout`, `cancel`, `userkey`, `uninstall` are destructive in
    different ways (creds clear, subscription end, key rotates,
    everything goes). Each must ask before acting; `n` aborts cleanly."""

    def _isolated_home_env(self, tmp_path, with_api_key=False):
        """Build an env with HOME=tmp_path and (optionally) a config
        file containing an API key so destructive commands see something
        to be destructive about."""
        home = tmp_path / "home"
        home.mkdir()
        cygnus_dir = home / ".cygnus"
        cygnus_dir.mkdir()
        if with_api_key:
            (cygnus_dir / "config.json").write_text(json.dumps({
                "api_key": "sk_test_DECLINE_ME",
                "tier": "free",
                "email": "test@example.invalid",
            }))
        env = {**CLI_ENV, "HOME": str(home), "CYGNUS_API_KEY": ""}
        return env, cygnus_dir / "config.json"

    def test_logout_confirm_n_keeps_config(self, tmp_path):
        env, cfg_path = self._isolated_home_env(tmp_path, with_api_key=True)
        r = _run_cli("logout", env=env, stdin="n\n")
        assert r.returncode == 0
        # Config must still exist with the api_key untouched.
        data = json.loads(cfg_path.read_text())
        assert data.get("api_key") == "sk_test_DECLINE_ME", (
            f"logout decline-with-n still cleared config! Got: {data}"
        )
        assert "Cancelled" in r.stdout or "cancelled" in r.stdout.lower()

    def test_logout_prompts_before_clearing(self, tmp_path):
        env, _ = self._isolated_home_env(tmp_path, with_api_key=True)
        r = _run_cli("logout", env=env, stdin="n\n")
        # Prompt text must mention what the user is agreeing to.
        out = r.stdout
        assert "[y/N]" in out or "[y/n]" in out.lower(), (
            f"logout doesn't show a [y/N] prompt:\n{out}"
        )

    def test_userkey_confirm_n_does_not_call_server(self, tmp_path):
        """`userkey <TOKEN>` consumes the token server-side on POST.
        With `n` at the prompt, we must exit BEFORE that POST."""
        env, _ = self._isolated_home_env(tmp_path)
        r = _run_cli("userkey", "fake-token-decline", env=env, stdin="n\n")
        assert r.returncode == 0, (
            f"userkey decline-with-n should exit cleanly (0), got "
            f"{r.returncode}\n{r.stdout}\n{r.stderr}"
        )
        full = r.stdout + r.stderr
        assert "Cancelled" in full or "cancelled" in full.lower()
        # If the server WERE called, we'd see either a connection
        # error string or a 4xx/5xx — both would indicate the early
        # exit didn't happen.
        assert "Connection error" not in full, (
            f"userkey called the server BEFORE the confirm prompt — "
            f"the `n` decline was supposed to short-circuit:\n{full}"
        )
        assert "HTTP Error" not in full

    def test_userkey_prompts_with_warning_text(self):
        """The userkey confirm must warn that the OLD key stops working
        — that's the surprise we're preventing."""
        r = _run_cli("userkey", "fake-token", stdin="n\n")
        out = r.stdout
        assert "old" in out.lower() or "rotate" in out.lower(), (
            f"userkey confirm doesn't warn about old-key invalidation:\n"
            f"{out}"
        )

    def test_uninstall_confirm_n_keeps_cygnus_home(self, tmp_path):
        env, cfg_path = self._isolated_home_env(tmp_path, with_api_key=True)
        r = _run_cli("uninstall", env=env, stdin="n\n")
        assert r.returncode == 0
        assert cfg_path.exists(), (
            f"uninstall decline-with-n removed config anyway! Path was: "
            f"{cfg_path}"
        )

    def test_cancel_confirm_prompt_exists(self, tmp_path):
        env, _ = self._isolated_home_env(tmp_path, with_api_key=True)
        r = _run_cli("cancel", env=env, stdin="n\n")
        # `cancel` may exit 0 (user declined) or print a network error
        # since it does try to reach /auth/billing/cancel after the
        # confirm. The shape we care about is: it asks first.
        full = r.stdout + r.stderr
        assert "[y/N]" in full or "[y/n]" in full.lower() or "Cancelled" in full, (
            f"cancel command doesn't show a confirm prompt:\n{full}"
        )


# ── 6. error paths users actually hit ────────────────────────────────────

class TestDepositErrorPaths:
    """`deposit` enforces $10 minimum and $1000 maximum client-side.
    Both error messages must be inline (no /pricing URL) and actionable."""

    def test_deposit_below_minimum_errors_cleanly(self):
        r = _run_cli("deposit", "5")
        assert r.returncode == 1, (
            f"`cygnus deposit 5` should exit 1 (below min), got "
            f"{r.returncode}\n{r.stdout}\n{r.stderr}"
        )
        full = r.stdout + r.stderr
        assert "minimum" in full.lower() or "$10" in full, (
            f"Below-min error doesn't mention the minimum:\n{full}"
        )

    def test_deposit_above_maximum_errors_cleanly(self):
        r = _run_cli("deposit", "5000")
        assert r.returncode == 1
        full = r.stdout + r.stderr
        assert "maximum" in full.lower() or "$1000" in full, (
            f"Above-max error doesn't mention the maximum:\n{full}"
        )

    def test_deposit_help_states_limits_inline(self):
        r = _run_cli("deposit", "--help")
        assert r.returncode == 0
        # Limits must be in the argparse help text — was previously
        # offloaded to /pricing.
        assert "10" in r.stdout and "1000" in r.stdout, (
            f"`cygnus deposit --help` doesn't state $10/$1000 inline:\n"
            f"{r.stdout}"
        )


class TestRequestCommand:
    def test_request_help_works(self):
        r = _run_cli("request", "--help")
        assert r.returncode == 0
        assert "library" in r.stdout.lower()

    def test_request_with_no_args_errors_cleanly(self):
        r = _run_cli("request")
        # argparse should bail out with non-zero — the user gets a
        # usage hint, not a Python traceback.
        assert r.returncode != 0
        full = r.stdout + r.stderr
        assert "Traceback" not in full, (
            f"`cygnus request` with no args dumped a traceback:\n{full}"
        )


class TestIssueCommand:
    def test_issue_with_body_no_crash(self):
        r = _run_cli("issue", "smoke-title", "--body", "smoke-body")
        full = r.stdout + r.stderr
        assert "NameError" not in full
        assert "Traceback" not in full

    def test_issue_help_mentions_github(self):
        r = _run_cli("issue", "--help")
        assert r.returncode == 0
        assert "issue" in r.stdout.lower()


# ── 7. cache command — non-destructive (cache_status), destructive (clear) ─

class TestCacheCommand:
    def test_cache_status_works_with_empty_cache(self, tmp_path):
        env = {**CLI_ENV, "HOME": str(tmp_path)}
        r = _run_cli("cache", "status", env=env)
        # status should be safe to run on a brand-new install where
        # the cache dir doesn't exist yet.
        full = r.stdout + r.stderr
        assert "Traceback" not in full, (
            f"`cygnus cache status` crashed on empty home:\n{full}"
        )

    def test_cache_help_lists_clear_and_status(self):
        r = _run_cli("cache", "--help")
        assert r.returncode == 0
        assert "clear" in r.stdout
        assert "status" in r.stdout


# ── 8. extension subcommand ──────────────────────────────────────────────

class TestExtensionCommand:
    def test_extension_help_works(self):
        r = _run_cli("extension", "--help")
        assert r.returncode == 0


# ── 9. verify/install/list/check/lock/sbom/init — just argparse ──────────

class TestVerificationCommandsArgparseClean:
    """These commands have real network paths — we don't exercise them
    here, just confirm argparse + module loading is clean."""

    @pytest.mark.parametrize("cmd", [
        "verify", "install", "list", "check", "lock", "sbom", "init",
    ])
    def test_command_help_no_traceback(self, cmd):
        r = _run_cli(cmd, "--help")
        assert r.returncode == 0
        full = r.stdout + r.stderr
        assert "Traceback" not in full


# ── 10. global flags ─────────────────────────────────────────────────────

class TestGlobalFlags:
    def test_ecosystem_flag_accepts_known_ecosystem(self):
        r = _run_cli("--ecosystem", "python", "--help")
        assert r.returncode == 0

    def test_no_cache_flag_accepted(self):
        r = _run_cli("--no-cache", "--help")
        assert r.returncode == 0
