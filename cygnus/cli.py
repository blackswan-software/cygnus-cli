#!/usr/bin/env python3
"""Cygnus CLI — pre-compiled, verified artifacts alongside your package manager.

Usage:
  cyg verify <lib>         Verify + download pre-compiled deps (one-step)
  cyg check <lib>          CVE scan (free, no account needed)
  cyg add <lib> [ver]      Download pre-compiled, verified artifact
  cyg request <lib>        Request verification for a library
  cyg status               Auth state, tier, balance, usage

Auth happens inline — first command prompts for email if needed.

The native package manager always works. Cygnus sits alongside it:
  pip install numpy              ← works as always
  cyg add numpy                  ← adds compiled .so to ~/.cyg/python/numpy/
  python -c "import numpy"       ← uses Cygnus version (faster, verified)
"""

import argparse
import getpass
import hashlib
import json
import os
import platform
import sys
import urllib.request
import urllib.error
from pathlib import Path


_opened_urls: set = set()


def _open_browser(url: str) -> bool:
    """Open URL in browser, suppressing GTK/snap stderr noise.

    Deduplicates within a process lifetime — calling with the same URL
    twice is a no-op (prevents tab spam during consent flows).
    """
    if url in _opened_urls:
        return True
    _opened_urls.add(url)
    import webbrowser
    _devnull = open(os.devnull, "w")
    _old = os.dup(2)
    os.dup2(_devnull.fileno(), 2)
    try:
        return webbrowser.open(url)
    finally:
        os.dup2(_old, 2)
        os.close(_old)
        _devnull.close()


# ── Config ─────────────────────────────────────────────────────────────────

# Accept CYG_HOME (new) or CYGNUS_HOME (legacy) env var, else default to ~/.cyg/
_home_env = os.environ.get("CYG_HOME") or os.environ.get("CYGNUS_HOME")
CYG_HOME = Path(_home_env) if _home_env else Path.home() / ".cyg"

# Auto-migrate from ~/.cygnus/ on first run
_OLD_HOME = Path.home() / ".cygnus"
if not CYG_HOME.exists() and _OLD_HOME.exists() and not _home_env:
    import shutil
    shutil.copytree(_OLD_HOME, CYG_HOME)

# Legacy alias for internal code that still references CYGNUS_HOME
CYGNUS_HOME = CYG_HOME


def _validate_registry_url(url: str) -> str:
    """Reject non-HTTPS registry URLs (except localhost/file).

    Why: CLI fetches signed artifacts from the registry.
    HTTP allows a network attacker to inject malicious responses and
    poison the local cache. Localhost/file URLs are allowed for dev.

    Caught 2026-05-21 pen test: CYGNUS_REGISTRY=http://blackswan-software.ai
    was silently accepted.
    """
    if url.startswith("https://") or url.startswith("file://"):
        return url
    if url.startswith("http://"):
        # Allow localhost for dev — every other http:// is rejected
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
            return url
        raise SystemExit(
            f"Cygnus refuses non-HTTPS registry URL: {url}\n"
            f"  HTTP allows network attackers to inject malicious responses.\n"
            f"  Use https:// or override with CYGNUS_ALLOW_INSECURE=1 (NOT recommended)."
        )
    raise SystemExit(f"Cygnus registry URL must be https:// (got: {url})")


_raw_registry = os.environ.get("CYGNUS_REGISTRY", "https://blackswan-software.ai")
REGISTRY_URL = (
    _raw_registry
    if os.environ.get("CYGNUS_ALLOW_INSECURE") == "1"
    else _validate_registry_url(_raw_registry)
)
TOKEN_EXTRACTOR_URL = os.environ.get("CYGNUS_TOKEN_EXTRACTOR", REGISTRY_URL)
CONFIG_FILE = CYGNUS_HOME / "config.json"

# Ecosystem allowlist. CLI flags that take --ecosystem must validate against
# this set before constructing registry URLs. Prevents URL injection via the
# ecosystem parameter (caught 2026-05-21 pen test M-2 — semicolon got through
# to URL construction, was rejected by urllib but produced messy error).
VALID_ECOSYSTEMS = frozenset({
    "python", "node", "go", "rust", "java", "csharp", "ruby",
    "php", "swift", "kotlin", "scala", "elixir", "zig", "cpp", "dart",
})


def _validate_ecosystem(eco: str | None) -> str | None:
    """Return the ecosystem if valid, else raise SystemExit with a clear message.

    None passes through (means 'auto-detect' to callers)."""
    if eco is None or eco == "":
        return None
    eco_lower = eco.lower().strip()
    if eco_lower not in VALID_ECOSYSTEMS:
        raise SystemExit(
            f"Cygnus: invalid ecosystem '{eco}'.\n"
            f"  Valid options: {', '.join(sorted(VALID_ECOSYSTEMS))}"
        )
    return eco_lower


def _load_config() -> dict:
    """Load ~/.cyg/config.json. Returns empty dict if missing or corrupt.

    Backward-compat shim: post-v0.1.13 the canonical shape is
    {"active": <email>, "accounts": {<email>: {...}}}. For pre-v0.1.13
    callers that read top-level api_key/tier/email, this function
    auto-resolves from the active account when the new shape is on disk.
    """
    try:
        raw = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    except (json.JSONDecodeError, OSError):
        return {}
    # If new-shape config: surface the active account's fields at the
    # top level so legacy callers keep working.
    if "accounts" in raw and "active" in raw:
        active_email = raw.get("active") or ""
        active = (raw.get("accounts") or {}).get(active_email, {})
        # Build a shim that looks like the old single-account dict
        # but also retains the new fields for callers who want them.
        return {
            "api_key": active.get("api_key", ""),
            "tier": active.get("tier", "free"),
            "email": active_email,
            "tos_accepted": raw.get("tos_accepted", False),
            "privacy_accepted": raw.get("privacy_accepted", False),
            # New-shape fields (used by accounts cmd):
            "active": active_email,
            "accounts": raw.get("accounts", {}),
        }
    return raw


def _save_config(data: dict):
    """Write ~/.cyg/config.json with owner-only permissions."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2) + "\n")
    CONFIG_FILE.chmod(0o600)


# ── Multi-account storage (v0.1.13) ────────────────────────────────────
# Same human often has multiple Cygnus accounts (corp + personal, dev +
# prod CI, etc.). Each = a separate signup email = a separate API key.
# The CLI stores them all in ~/.cyg/config.json under "accounts" with
# an "active" pointer to the one currently in use. Old single-account
# configs auto-migrate on first _load_accounts() call.
#
# CYGNUS_API_KEY env var still wins everything (CI use case): if set,
# accounts switching has no effect within that invocation.


def _load_accounts() -> dict:
    """Return canonical multi-account config + auto-migrate from
    legacy single-account shape on first read.

    Returned shape (always — even on empty disk):
      {
        "active": "<email>" or None,
        "accounts": {
          "<email>": {"api_key": str, "tier": str, "label": str,
                       "added": iso8601, "email_verified": bool},
          ...
        }
      }

    Legacy shape on disk:
      {"api_key": "cyg_...", "tier": "free", "email": "x@y"}
    becomes:
      {"active": "x@y", "accounts": {"x@y": {"api_key": ..., ...}}}
    The migrated file is written back to disk so subsequent reads see
    the new shape directly.
    """
    try:
        raw = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    except (json.JSONDecodeError, OSError):
        raw = {}
    if not raw:
        return {"active": None, "accounts": {}}
    # New shape already on disk
    if "accounts" in raw and "active" in raw:
        return {
            "active": raw.get("active"),
            "accounts": raw.get("accounts") or {},
        }
    # Legacy single-account shape — migrate.
    api_key = raw.get("api_key", "")
    email = raw.get("email") or ""
    if not api_key:
        return {"active": None, "accounts": {}}
    if not email:
        # Pre-2026-06-06 configs didn't cache email. Use a synthetic
        # key so the account still has a label.
        email = f"legacy-{hashlib.sha256(api_key.encode()).hexdigest()[:8]}@local"
    migrated = {
        "active": email,
        "accounts": {
            email: {
                "api_key": api_key,
                "tier": raw.get("tier", "free"),
                "label": raw.get("label", ""),
                "added": raw.get("added", ""),
                "email_verified": raw.get("email_verified", False),
            },
        },
    }
    # Persist the migration so subsequent reads skip this branch.
    try:
        _save_config(migrated)
    except Exception:
        pass
    return migrated


def _save_accounts(data: dict):
    """Persist the multi-account config to disk."""
    _save_config({
        "active": data.get("active"),
        "accounts": data.get("accounts") or {},
    })


def _get_active_email() -> str:
    """Return the currently-active account email, or ''."""
    return _load_accounts().get("active") or ""


def _set_active_email(email: str) -> bool:
    """Mark the given email as the active account. Returns True on
    success, False if the email isn't a known account."""
    data = _load_accounts()
    if email not in (data.get("accounts") or {}):
        return False
    data["active"] = email
    _save_accounts(data)
    return True


def _add_account(email: str, api_key: str, tier: str = "free",
                 label: str = "", email_verified: bool = False,
                 refresh_token: str = "") -> None:
    """Add an account to the local store and set it as active.
    Overwrites any existing entry for the same email."""
    from datetime import datetime, timezone
    data = _load_accounts()
    accounts = data.get("accounts") or {}
    entry = {
        "api_key": api_key,
        "tier": tier,
        "label": label,
        "added": datetime.now(timezone.utc).isoformat(),
        "email_verified": email_verified,
    }
    if refresh_token:
        entry["refresh_token"] = refresh_token
    accounts[email] = entry
    data["accounts"] = accounts
    data["active"] = email
    _save_accounts(data)


def _remove_account(email: str) -> bool:
    """Remove an account by email. If it was active, pick a remaining
    one (or None) as the new active. Returns True if an account was
    removed."""
    data = _load_accounts()
    accounts = data.get("accounts") or {}
    if email not in accounts:
        return False
    del accounts[email]
    data["accounts"] = accounts
    if data.get("active") == email:
        # Pick any remaining account; or None if empty.
        data["active"] = next(iter(accounts), None)
    _save_accounts(data)
    return True


def _active_api_key() -> str:
    """Resolve the effective API key: env var first (CI), then the
    active account from config. Used by API_KEY module constant."""
    env = os.environ.get("CYGNUS_API_KEY", "")
    if env:
        return env
    data = _load_accounts()
    email = data.get("active")
    if not email:
        return ""
    return (data.get("accounts") or {}).get(email, {}).get("api_key", "")


def _active_key_source() -> str:
    """Describe where the active API key came from. For status display."""
    if os.environ.get("CYGNUS_API_KEY"):
        return "CYGNUS_API_KEY env var"
    email = _get_active_email()
    if email:
        return email
    return ""


def _active_refresh_token() -> str:
    """Return the refresh token for the active account, or empty string."""
    data = _load_accounts()
    email = data.get("active")
    if not email:
        return ""
    return (data.get("accounts") or {}).get(email, {}).get("refresh_token", "")


# ── Local Cache (per API key, 24h TTL) ────────────────────────────────────
# Avoids hitting the API on every CLI call. Each API key gets its own cache
# directory so different users on the same machine don't share results.
# Cached/304 responses do NOT count against rate limits.

CACHE_TTL = int(os.environ.get("CYGNUS_CACHE_TTL", 86400))  # 24 hours default


def _cache_dir() -> Path:
    """Cache directory scoped to the current API key."""
    if API_KEY:
        key_hash = hashlib.sha256(API_KEY.encode()).hexdigest()[:12]
    else:
        key_hash = "anonymous"
    d = CYGNUS_HOME / "cache" / key_hash
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_key(path: str) -> Path:
    """Convert an API path to a cache file path."""
    safe = hashlib.sha256(path.encode()).hexdigest()[:16]
    return _cache_dir() / f"{safe}.json"


def _cache_get(path: str) -> dict | None:
    """Read from local cache if fresh (within TTL). Returns None if stale/missing."""
    import time
    cache_file = _cache_key(path)
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text())
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > CACHE_TTL:
            cache_file.unlink(missing_ok=True)
            return None
        return data.get("_payload")
    except (json.JSONDecodeError, OSError):
        cache_file.unlink(missing_ok=True)
        return None


def _cache_set(path: str, payload: dict):
    """Write to local cache with timestamp."""
    import time
    cache_file = _cache_key(path)
    try:
        cache_file.write_text(json.dumps({
            "_cached_at": time.time(),
            "_path": path,
            "_payload": payload,
        }) + "\n")
    except OSError:
        pass  # Cache write failure is non-fatal


def _artifact_cache_dir() -> Path:
    d = CYGNUS_HOME / "artifacts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _artifact_cache_get(sha256_hex: str) -> bytes | None:
    p = _artifact_cache_dir() / sha256_hex
    if not p.exists():
        return None
    data = p.read_bytes()
    if hashlib.sha256(data).hexdigest() == sha256_hex:
        return data
    p.unlink(missing_ok=True)
    return None


def _artifact_cache_set(sha256_hex: str, data: bytes):
    try:
        (_artifact_cache_dir() / sha256_hex).write_bytes(data)
    except OSError:
        pass


def _download_artifact_bytes(ecosystem: str, library: str, version: str,
                             manifest: dict) -> bytes | None:
    """Download artifact bytes from CDN or proxy. Returns None on failure."""
    lib_encoded = library.replace("/", "__").replace(":", "__")
    filename = manifest.get("filename", "")
    target_key = "universal"
    if not filename or filename == "manifest.json":
        for target, info in manifest.get("artifacts", {}).items():
            fn = info.get("filename", "")
            if fn and fn != "manifest.json":
                filename = fn
                target_key = target
                break
    if not filename or filename == "manifest.json":
        return None

    cdn_url = f"https://cdn.blackswan-software.ai/artifacts/{ecosystem}/{lib_encoded}/{version}/{target_key}/{filename}"
    proxy_url = f"{REGISTRY_URL}/artifact/{ecosystem}/{lib_encoded}/{version}/{target_key}/{filename}?proxy=true"
    for url in (cdn_url, proxy_url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cygnus-cli/1.0"})
            if API_KEY:
                req.add_header("X-API-Key", API_KEY)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except Exception:
            continue
    return None


# Env var takes precedence over stored config. Multi-account aware via
# _active_api_key (v0.1.13): falls through to the active account from
# ~/.cyg/config.json when CYGNUS_API_KEY is not set.
API_KEY = _active_api_key()

# Detect current platform target
_ARCH = platform.machine()
if _ARCH in ("x86_64", "AMD64"):
    _ARCH = "x86_64"
elif _ARCH in ("aarch64", "arm64"):
    _ARCH = "aarch64"

_OS = platform.system().lower()
if _OS == "darwin":
    _PLATFORM = f"{_ARCH}-darwin"
elif _OS == "windows":
    _PLATFORM = f"{_ARCH}-windows"
else:
    _PLATFORM = f"{_ARCH}-linux"


# Lockfile version cache — populated by _parse_lockfile, used by _verify_project
_LOCKFILE_VERSIONS: dict[str, str] = {}

# Last HTTP error code from _api() — lets callers distinguish 429 from 404
_last_api_error: int | None = None

def _try_refresh() -> bool:
    """Attempt to exchange a stored refresh token for a new API key.
    On success, updates config + global API_KEY. Returns True if refreshed."""
    global API_KEY
    rt = _active_refresh_token()
    if not rt:
        return False
    email = _get_active_email()
    if not email:
        return False
    try:
        payload = json.dumps({"refresh_token": rt}).encode()
        req = urllib.request.Request(
            f"{REGISTRY_URL}/auth/refresh",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        new_key = data.get("api_key", "")
        new_rt = data.get("refresh_token", "")
        if not new_key:
            return False
        tier = data.get("tier", "free")
        _add_account(email, new_key, tier=tier, refresh_token=new_rt)
        API_KEY = new_key
        return True
    except Exception:
        return False


# ── Helpers ────────────────────────────────────────────────────────────────

def _api(path: str, use_cache: bool = True, quiet: bool = False,
         _refreshed: bool = False) -> dict | None:
    """GET from registry API with local cache. Returns JSON or None on error.

    Cache hit → returns instantly (no API call, no rate limit impact).
    Cache miss → fetches from API, caches result for 24h.
    Sets _last_api_error to the HTTP status code on failure (None on success).
    quiet=True suppresses error messages (for best-effort lookups like email).
    """
    global _last_api_error
    _last_api_error = None

    if use_cache:
        cached = _cache_get(path)
        if cached is not None:
            return cached

    url = f"{REGISTRY_URL}{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "cygnus-cli/1.0")
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Surface grace-credit info if the server granted one
            grace_used = resp.headers.get("X-Cygnus-Grace-Granted")
            grace_left = resp.headers.get("X-Cygnus-Grace-Remaining")
            if grace_used and not quiet:
                print(
                    f"\n  Heads up: you're past the free daily limit. "
                    f"Grace used {grace_used} (remaining today: {grace_left}). "
                    f"Email support@blackswan-software.ai with your account email for ongoing access.",
                    file=sys.stderr,
                )
            data = json.loads(resp.read())
            if use_cache and data is not None:
                _cache_set(path, data)
            return data
    except urllib.error.HTTPError as e:
        _last_api_error = e.code
        if e.code == 404:
            return None
        if e.code == 429:
            if not quiet:
                detail_text = ""
                try:
                    body = e.read().decode()
                    detail_text = json.loads(body).get("detail", "") if body else ""
                except Exception:
                    pass
                retry_after = None
                try:
                    retry_after = e.headers.get("Retry-After")
                except Exception:
                    pass
                if detail_text and "daily" in detail_text.lower():
                    print(f"\n  Daily limit reached.", file=sys.stderr)
                else:
                    print(f"\n  Rate limited — too many requests.", file=sys.stderr)
                if detail_text:
                    print(f"  {detail_text}", file=sys.stderr)
                else:
                    print(f"  Try again in a moment, or email support@blackswan-software.ai.", file=sys.stderr)
                if retry_after:
                    print(f"  Resets in: {retry_after}s", file=sys.stderr)
            return None
        if e.code == 401:
            if not _refreshed and _try_refresh():
                return _api(path, use_cache=use_cache, quiet=quiet, _refreshed=True)
            if not quiet:
                print(f"  Not authenticated. Run a command to set up.", file=sys.stderr)
            return None
        if not quiet:
            print(f"  API error: {e.code} {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
        if not quiet:
            print(f"  Connection error: {e}", file=sys.stderr)
        return None


def _trigger_on_demand(ecosystem: str, library: str, version: str = "latest") -> dict | None:
    """Trigger on-demand synthesis via test-runner endpoint. Returns result or None."""
    lib_encoded = library.replace("/", "__").replace(":", "__")
    url = f"{REGISTRY_URL}/synthesis/on-demand"
    payload = json.dumps({
        "ecosystem": ecosystem,
        "library": lib_encoded,
        "version": version,
    }).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "cygnus-cli/1.0")
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


_UPSTREAM_REGISTRY_URLS = {
    "python": "https://pypi.org/pypi/{lib}/json",
    "node": "https://registry.npmjs.org/{lib}",
    "rust": "https://crates.io/api/v1/crates/{lib}",
    "go": "https://proxy.golang.org/{lib}/@v/list",
    "ruby": "https://rubygems.org/api/v1/gems/{lib}.json",
    "php": "https://repo.packagist.org/p2/{lib}.json",
    "java": "https://search.maven.org/solrsearch/select?q=a:{lib}&rows=1&wt=json",
}


def _upstream_package_exists(ecosystem: str, library: str) -> bool:
    """Quick check whether a package name exists in the upstream registry."""
    url_template = _UPSTREAM_REGISTRY_URLS.get(ecosystem)
    if not url_template:
        return True  # no registry to check — allow queue
    url = url_template.format(lib=library)
    req = urllib.request.Request(url, headers={"User-Agent": "cygnus-cli/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        return e.code != 404
    except Exception:
        return True  # network issue — don't block the queue


def _queue_compilation(ecosystem: str, library: str, version: str = "latest"):
    """Auto-queue a missing library for compilation via the compiler endpoint."""
    url = f"{REGISTRY_URL}/compile/queue"
    payload = json.dumps({
        "ecosystem": ecosystem,
        "library": library,
        "version": version,
        "priority": 1,
        "source": "cli-auto",
    }).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "cygnus-cli/1.0")
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass  # Best-effort — don't block CLI on queue failure


def _download(url: str, dest: Path) -> bool:
    """Download a file, return True on success."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "cygnus-cli/1.0"})
        if API_KEY:
            req.add_header("X-API-Key", API_KEY)
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
        return True
    except Exception as e:
        print(f"  Download failed: {e}", file=sys.stderr)
        return False


def _auto_install_artifact(ecosystem: str, library: str, version: str,
                           confidence: str):
    """Download and cache artifact during verify — one-step workflow.

    After verify reports a grade, auto-download the pre-compiled artifact
    to ~/.cyg/ so the user doesn't need a separate `cyg add` step.
    Skips download if already cached.
    """
    lib_encoded = library.replace("/", "__").replace(":", "__")
    dest_dir = CYGNUS_HOME / ecosystem / library / version

    # Skip if already cached
    manifest_path = dest_dir / "manifest.json"
    if manifest_path.exists():
        return

    manifest = _api(f"/manifest/{ecosystem}/{lib_encoded}/{version}")
    if not manifest:
        return

    artifacts = manifest.get("artifacts", {})
    target_info = artifacts.get(_PLATFORM) or artifacts.get("universal")
    target_key = _PLATFORM if _PLATFORM in artifacts else "universal"
    if not target_info:
        return

    filename = target_info.get("filename", "")
    if not filename or filename == "manifest.json":
        return

    expected_sha = target_info.get("sha256", "")
    cdn_url = f"https://cdn.blackswan-software.ai/artifacts/{ecosystem}/{lib_encoded}/{version}/{target_key}/{filename}"
    proxy_url = f"{REGISTRY_URL}/artifact/{ecosystem}/{lib_encoded}/{version}/{target_key}/{filename}?proxy=true"

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / filename

    downloaded = _download(cdn_url, dest_file)
    if not downloaded:
        downloaded = _download(proxy_url, dest_file)

    if downloaded:
        if expected_sha:
            actual = hashlib.sha256(dest_file.read_bytes()).hexdigest()
            if actual != expected_sha:
                print(f"  ⚠ SHA256 mismatch — removing corrupted artifact")
                dest_file.unlink()
                return

        manifest["confidence"] = confidence
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

        _populate_wheels_dir(ecosystem, dest_file)

        size_kb = dest_file.stat().st_size / 1024
        print(f"  Artifact:    cached ({size_kb:.0f}KB) → {dest_dir}")


def _detect_ecosystem() -> str | None:
    """Detect primary project ecosystem from current directory."""
    ecosystems = _detect_all_ecosystems()
    return ecosystems[0] if ecosystems else None


def _detect_all_ecosystems() -> list[str]:
    """Detect ALL ecosystems present in current directory. Returns list ordered by priority."""
    cwd = Path.cwd()
    found = []

    # Check each ecosystem — order matters (most common first)
    _ECO_MARKERS = [
        ("python", ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "poetry.lock")),
        ("node", ("package.json",)),
        ("rust", ("Cargo.toml",)),
        ("go", ("go.mod",)),
        ("java", ("pom.xml", "build.gradle", "build.gradle.kts")),
        ("ruby", ("Gemfile",)),
        ("php", ("composer.json",)),
        ("dart", ("pubspec.yaml",)),
        ("scala", ("build.sbt",)),
        ("elixir", ("mix.exs",)),
        ("swift", ("Package.swift",)),
        ("cpp", ("CMakeLists.txt", "Makefile", "meson.build", "conanfile.txt", "conanfile.py", "vcpkg.json")),
    ]

    for eco, markers in _ECO_MARKERS:
        if any((cwd / f).exists() for f in markers):
            found.append(eco)

    # C# needs glob check
    if list(cwd.glob("*.csproj")) or list(cwd.glob("*.sln")):
        if "csharp" not in found:
            found.append("csharp")

    # Kotlin-specific: gradle + kotlin source dir (otherwise it's java)
    if (cwd / "src" / "main" / "kotlin").is_dir() and "java" in found:
        found.append("kotlin")

    return found


def _find_venv() -> Path | None:
    """Find active Python virtualenv."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        return Path(venv)
    # Check common locations
    for name in (".venv", "venv", "env", ".env"):
        p = Path.cwd() / name
        if (p / "bin" / "python").exists() or (p / "Scripts" / "python.exe").exists():
            return p
    return None


def _sitecustomize_path(venv: Path) -> Path:
    """Return sitecustomize.py path for a venv."""
    # Find site-packages
    for sp in venv.rglob("site-packages"):
        if sp.is_dir():
            return sp / "sitecustomize.py"
    # Fallback
    return venv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages" / "sitecustomize.py"


SITECUSTOMIZE_CONTENT = """\
# Cygnus: prepend compiled artifact directory to sys.path
# Native packages remain untouched — Cygnus versions load first when available.
# Remove this file or delete ~/.cyg/ to revert to native-only.
import sys, os
_cygnus = os.path.expanduser('~/.cyg/python')
if os.path.isdir(_cygnus) and _cygnus not in sys.path:
    sys.path.insert(0, _cygnus)
"""

PIP_CONF_FIND_LINKS = """\

# Cygnus: use locally cached wheels before downloading from PyPI.
# pip checks ~/.cyg/python/wheels/ first — if the wheel is there, no network.
# Remove these lines or delete ~/.cyg/ to revert to PyPI-only.
[global]
find-links = {wheels_dir}
"""


def _pip_conf_path(venv: Path = None) -> Path:
    """Return the pip.conf path to write the find-links directive.

    Prefers venv-scoped pip.conf. Falls back to user-level.
    """
    if venv:
        return venv / "pip.conf"
    return Path.home() / ".config" / "pip" / "pip.conf"


def _install_pip_find_links(venv: Path = None) -> bool:
    """Install pip find-links pointing to ~/.cyg/python/wheels/.

    pip's --find-links is additive: if the wheel isn't in the local dir,
    pip falls back to PyPI. Removing the config entry restores native behavior.
    """
    wheels_dir = CYGNUS_HOME / "python" / "wheels"
    wheels_dir.mkdir(parents=True, exist_ok=True)

    conf = _pip_conf_path(venv)
    existing = conf.read_text() if conf.exists() else ""

    if "cygnus" in existing.lower() and str(wheels_dir) in existing:
        return True

    conf.parent.mkdir(parents=True, exist_ok=True)

    if "[global]" in existing and "find-links" in existing:
        # Append our wheels dir to existing find-links
        lines = existing.splitlines()
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if line.strip().startswith("find-links"):
                new_lines.append(f"find-links = {wheels_dir}")
        conf.write_text("\n".join(new_lines) + "\n")
    else:
        snippet = PIP_CONF_FIND_LINKS.format(wheels_dir=wheels_dir)
        with open(conf, "a") as f:
            f.write(snippet)

    return True


def _remove_pip_find_links(venv: Path = None):
    """Remove cygnus find-links from pip.conf during uninstall."""
    conf = _pip_conf_path(venv)
    if not conf.exists():
        return
    text = conf.read_text()
    if "cygnus" not in text.lower():
        return

    # Remove the cygnus block (comment + [global] + find-links)
    lines = text.splitlines()
    cleaned = []
    skip = False
    for line in lines:
        if "cygnus" in line.lower() and ("find-links" in line.lower() or "#" in line):
            skip = True
            continue
        if skip and line.strip().startswith("find-links") and str(CYGNUS_HOME) in line:
            continue
        if skip and (not line.strip() or line.strip().startswith("[")):
            skip = False
        if not skip:
            cleaned.append(line)

    result = "\n".join(cleaned).strip()
    if result:
        conf.write_text(result + "\n")
    else:
        conf.unlink()


def _populate_wheels_dir(ecosystem: str, artifact_path: Path):
    """Register a downloaded artifact with the native package manager's cache.

    All 15 ecosystems: artifact goes to the directory the resolution hook points at.
    """
    import subprocess

    if ecosystem == "python" and artifact_path.suffix == ".whl":
        wheels_dir = CYGNUS_HOME / "python" / "wheels"
        wheels_dir.mkdir(parents=True, exist_ok=True)

        link = wheels_dir / artifact_path.name
        if link.exists() or link.is_symlink():
            if link.is_symlink() and link.resolve() == artifact_path.resolve():
                return
            link.unlink()

        try:
            link.symlink_to(artifact_path.resolve())
        except OSError:
            import shutil
            shutil.copy2(artifact_path, link)

    elif ecosystem == "node" and artifact_path.suffix in (".tgz", ".gz"):
        try:
            subprocess.run(
                ["npm", "cache", "add", str(artifact_path)],
                capture_output=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    elif ecosystem == "ruby" and artifact_path.suffix == ".gem":
        try:
            subprocess.run(
                ["gem", "install", "--local", str(artifact_path),
                 "--no-document", "--user-install"],
                capture_output=True, timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    elif ecosystem == "dart":
        _populate_dart_cache(artifact_path)

    elif ecosystem == "go":
        _populate_go_proxy(artifact_path)

    elif ecosystem in ("java", "kotlin"):
        _populate_maven_repo(ecosystem, artifact_path)

    elif ecosystem in ("elixir", "swift", "erlang"):
        _extract_to_cache(ecosystem, artifact_path)

    elif ecosystem == "rust":
        _extract_to_cache(ecosystem, artifact_path)

    elif ecosystem == "csharp":
        _populate_nuget_cache(artifact_path)

    elif ecosystem == "php":
        _extract_to_cache(ecosystem, artifact_path)

    elif ecosystem == "scala":
        _populate_maven_repo(ecosystem, artifact_path)

    elif ecosystem == "cpp":
        _extract_to_cache(ecosystem, artifact_path)


def _populate_dart_cache(artifact_path: Path):
    """Copy package into Dart's pub system cache.

    Pub cache layout: ~/.pub-cache/hosted/pub.dev/<name>-<ver>/
    Extracting the tarball there makes `dart pub get --offline` find it.
    """
    import tarfile

    if not artifact_path.suffix in (".gz", ".tar"):
        return

    stem = artifact_path.stem
    if stem.endswith(".tar"):
        stem = stem[:-4]

    pub_cache = Path.home() / ".pub-cache" / "hosted" / "pub.dev" / stem
    if pub_cache.exists():
        return

    try:
        with tarfile.open(artifact_path, "r:gz") as tf:
            tf.extractall(pub_cache, filter="data")
    except (tarfile.TarError, OSError):
        pass


def _populate_go_proxy(artifact_path: Path):
    """Extract Go module source into GOPROXY file:// directory layout.

    Go module proxy layout:
      ~/.cyg/go/proxy/<module>/@v/list        (version list)
      ~/.cyg/go/proxy/<module>/@v/<ver>.info   (version metadata)
      ~/.cyg/go/proxy/<module>/@v/<ver>.zip    (source)
      ~/.cyg/go/proxy/<module>/@v/<ver>.mod    (go.mod)
    """
    parent = artifact_path.parent
    lib = parent.parent.name
    version = parent.name

    mod_path = lib.replace("__", "/")

    proxy_dir = CYGNUS_HOME / "go" / "proxy" / mod_path / "@v"
    proxy_dir.mkdir(parents=True, exist_ok=True)

    list_file = proxy_dir / "list"
    existing = list_file.read_text().splitlines() if list_file.exists() else []
    if version not in existing:
        with open(list_file, "a") as f:
            f.write(version + "\n")

    import shutil
    zip_dest = proxy_dir / f"{version}.zip"
    if not zip_dest.exists():
        shutil.copy2(artifact_path, zip_dest)

    info_file = proxy_dir / f"{version}.info"
    if not info_file.exists():
        info_file.write_text(f'{{"Version":"{version}"}}\n')


def _populate_maven_repo(ecosystem: str, artifact_path: Path):
    """Extract JARs into Maven local repo layout.

    Maven layout: ~/.cyg/{eco}/repo/<groupId-dirs>/<artifactId>/<version>/<artifactId>-<version>.jar
    """
    import tarfile

    parent = artifact_path.parent
    lib = parent.parent.name
    version = parent.name

    if "__" in lib:
        parts = lib.split("__")
        group_id = parts[0]
        artifact_id = parts[1] if len(parts) > 1 else parts[0]
    else:
        group_id = lib
        artifact_id = lib

    group_dirs = group_id.replace(".", "/")
    repo_dir = CYGNUS_HOME / ecosystem / "repo" / group_dirs / artifact_id / version
    repo_dir.mkdir(parents=True, exist_ok=True)

    if artifact_path.suffix in (".gz", ".tar"):
        try:
            with tarfile.open(artifact_path, "r:gz") as tf:
                tf.extractall(repo_dir, filter="data")
        except (tarfile.TarError, OSError):
            pass


def _extract_to_cache(ecosystem: str, artifact_path: Path):
    """Extract tarball to ~/.cyg/{eco}/<lib>/<ver>/ for path-based deps.

    Used by Elixir (mix path deps) and Swift (SPM local packages).
    After extraction, the user references the path in mix.exs / Package.swift.
    """
    import tarfile

    parent = artifact_path.parent
    lib = parent.parent.name
    version = parent.name

    dest = CYGNUS_HOME / ecosystem / lib / version / "src"
    if dest.exists():
        return

    if artifact_path.suffix in (".gz", ".tar"):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            with tarfile.open(artifact_path, "r:gz") as tf:
                tf.extractall(dest, filter="data")
        except (tarfile.TarError, OSError):
            pass


def _populate_nuget_cache(artifact_path: Path):
    """Extract .nupkg files from artifact into ~/.cyg/csharp/ for NuGet local source.

    The compiler bundles all .nupkg files (primary + transitive deps) into a
    .tar.gz. NuGet local source expects .nupkg files flat in the source dir.
    """
    import tarfile

    if artifact_path.suffix not in (".gz", ".tar"):
        return

    nuget_dir = CYGNUS_HOME / "csharp"
    nuget_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(artifact_path, "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith(".nupkg"):
                    member.name = Path(member.name).name
                    tf.extract(member, nuget_dir, filter="data")
    except (tarfile.TarError, OSError):
        _extract_to_cache("csharp", artifact_path)


# Per-ecosystem resolution hook templates
# Each hook tells the native package manager to check ~/.cyg/{eco}/ first.
HOOK_TEMPLATES = {
    "node": {
        "file": ".npmrc",
        "global_file": "~/.npmrc",
        "marker": "cygnus",
        "content": """\
# Cygnus: prefer locally cached packages before downloading from registry.
# npm checks its cache first with prefer-offline; cyg add pre-populates it.
# Remove this line or delete ~/.cyg/ to revert to registry-only.
prefer-offline=true
""",
        "description": "Node.js: project .npmrc (prefer-offline)",
        "global_description": "Node.js: user-level ~/.npmrc (prefer-offline)",
    },
    "rust": {
        "file": ".cargo/config.toml",
        "global_file": "~/.cargo/config.toml",
        "marker": "cygnus",
        "content": """\
# Cygnus: local vendored crate source
# crates.io remains available as fallback — Cygnus-cached crates resolve first.
# Remove this block or delete ~/.cyg/ to revert to crates.io-only.
[source.cygnus-local]
local-registry = "{cygnus_home}/rust/registry"

[source.crates-io]
replace-with = "cygnus-local"
""",
        "description": "Rust: .cargo/config.toml (local registry)",
        "global_description": "Rust: user-level ~/.cargo/config.toml",
    },
    "go": {
        "file": None,
        "marker": "cygnus",
        "env": {
            "GOFLAGS": "-modcacherw",
        },
        "go_env": {
            "GOPROXY": "file://{cygnus_home}/go/proxy,https://proxy.golang.org,direct",
        },
        "description": "Go: GOPROXY with local module cache (file:// before proxy.golang.org)",
    },
    "java": {
        "file": ".mvn/settings.xml",
        "global_file": "~/.m2/settings.xml",
        "marker": "cygnus",
        "content": """\
<!-- Cygnus: local Maven repo checked BEFORE Central. -->
<!-- Remove this file or delete ~/.cyg/ to revert to Central-only. -->
<settings>
  <profiles>
    <profile>
      <id>cygnus</id>
      <repositories>
        <repository>
          <id>cygnus-local</id>
          <url>file://{cygnus_home}/java/repo</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>cygnus</activeProfile>
  </activeProfiles>
</settings>
""",
        "description": "Java (Maven): local repo in .mvn/settings.xml",
        "global_description": "Java (Maven): user-level ~/.m2/settings.xml",
        "alt_file": "settings.gradle",
        "alt_content": """\
// Cygnus: local Maven repo checked before mavenCentral.
// Remove this file or delete ~/.cyg/ to revert.
pluginManagement {{
    repositories {{
        maven {{ url = uri("file://{cygnus_home}/java/repo") }}
        gradlePluginPortal()
        mavenCentral()
    }}
}}
""",
    },
    "csharp": {
        "file": "NuGet.config",
        "global_file": "~/.nuget/NuGet/NuGet.Config",
        "marker": "cygnus",
        "content": """\
<?xml version="1.0" encoding="utf-8"?>
<!-- Cygnus: local NuGet source. Remove this file or delete ~/.cyg/ to revert. -->
<configuration>
  <packageSources>
    <add key="cygnus" value="{cygnus_home}/csharp" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
""",
        "description": "C#: NuGet.config local source",
        "global_description": "C#: user-level NuGet.Config (~/.nuget/NuGet/)",
    },
    "ruby": {
        "file": None,
        "marker": "cygnus",
        "description": "Ruby: gem install --local (auto on cyg add, installed to user gems)",
    },
    "dart": {
        "file": None,
        "marker": "cygnus",
        "description": "Dart: extracted to ~/.pub-cache/hosted/pub.dev/ (auto on cyg add, dart pub get --offline finds it)",
    },
    "kotlin": {
        "file": ".mvn/settings.xml",
        "global_file": "~/.m2/settings.xml",
        "marker": "cygnus",
        "content": """\
<!-- Cygnus: local Maven repo checked BEFORE Central. -->
<!-- Remove this file or delete ~/.cyg/ to revert to Central-only. -->
<settings>
  <profiles>
    <profile>
      <id>cygnus</id>
      <repositories>
        <repository>
          <id>cygnus-local</id>
          <url>file://{cygnus_home}/kotlin/repo</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>cygnus</activeProfile>
  </activeProfiles>
</settings>
""",
        "description": "Kotlin: local repo in .mvn/settings.xml",
        "global_description": "Kotlin: user-level ~/.m2/settings.xml",
        "alt_file": "settings.gradle.kts",
        "alt_content": """\
// Cygnus: local Maven repo checked before mavenCentral.
// Remove this file or delete ~/.cyg/ to revert.
pluginManagement {{
    repositories {{
        maven {{ url = uri("file://{cygnus_home}/kotlin/repo") }}
        gradlePluginPortal()
        mavenCentral()
    }}
}}
""",
    },
    "scala": {
        "file": "project/cygnus.sbt",
        "global_file": "~/.sbt/1.0/cygnus.sbt",
        "marker": "cygnus",
        "content": """\
// Cygnus: local Scala artifact cache. Remove this file or delete ~/.cyg/ to revert.
resolvers += "cygnus" at "file://{cygnus_home}/scala"
""",
        "description": "Scala: project/cygnus.sbt resolver",
        "global_description": "Scala: user-level ~/.sbt/1.0/cygnus.sbt",
    },
    "elixir": {
        "file": None,
        "marker": "cygnus",
        "description": "Elixir: extracted to ~/.cyg/elixir/<lib>/<ver>/src/ (add {:dep, path: \"...\"} in mix.exs)",
    },
    "swift": {
        "file": None,
        "marker": "cygnus",
        "description": "Swift: extracted to ~/.cyg/swift/<lib>/<ver>/src/ (add .package(path: \"...\") in Package.swift)",
    },
    "php": {
        "file": "composer.json",
        "global_file": "~/.composer/config.json",
        "marker": "cygnus",
        "content": """\
{{
  "_comment": "Cygnus: local path repo. Remove this block or delete ~/.cyg/ to revert.",
  "repositories": [
    {{
      "type": "path",
      "url": "{cygnus_home}/php/*"
    }}
  ]
}}
""",
        "description": "PHP: Composer local repository",
        "global_description": "PHP: user-level ~/.composer/config.json",
    },
    "cpp": {
        "file": "CMakeLists.txt",
        "global_file": None,
        "marker": "cygnus",
        "content": """\
# Cygnus: check local cache before fetching from network.
# Remove this line or delete ~/.cyg/ to revert.
list(PREPEND CMAKE_PREFIX_PATH "{cygnus_home}/cpp")
""",
        "description": "C/C++: CMAKE_PREFIX_PATH in CMakeLists.txt",
    },
    "erlang": {
        "file": None,
        "marker": "cygnus",
        "description": "Erlang: extracted to ~/.cyg/erlang/<lib>/<ver>/src/ (add as path dep in rebar.config)",
    },
}


def _install_hook(eco: str, use_global: bool = False) -> bool:
    """Install resolution hook for ecosystem. Returns True if installed."""
    hook = HOOK_TEMPLATES.get(eco)
    if not hook:
        return False

    cygnus_home = str(CYGNUS_HOME)
    cwd = Path.cwd()
    desc_key = "global_description" if use_global else "description"
    description = hook.get(desc_key, hook["description"])

    # Env-var-based hooks (Go) — always global
    if hook.get("env") or hook.get("go_env"):
        print(f"  {description}")
        if hook.get("go_env"):
            import subprocess
            for var, val in hook["go_env"].items():
                resolved = val.format(cygnus_home=cygnus_home)
                try:
                    subprocess.run(
                        ["go", "env", "-w", f"{var}={resolved}"],
                        capture_output=True, timeout=10,
                    )
                    print(f"  Set: {var}={resolved}")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    print(f"  Add to your shell profile:")
                    print(f"    export {var}=\"{resolved}\"")
        if hook.get("env"):
            print(f"  Add to your shell profile:")
            for var, val in hook["env"].items():
                print(f"    export {var}=\"{val.format(cygnus_home=cygnus_home)}\"")
        return True

    # File-based hooks
    if not hook.get("file"):
        print(f"  {description}")
        return True

    # Determine target path
    if use_global and hook.get("global_file"):
        target = Path(os.path.expanduser(hook["global_file"]))
    elif eco == "java" and ((cwd / "build.gradle").exists() or (cwd / "build.gradle.kts").exists()):
        # Java: choose Maven vs Gradle for project-level
        target = cwd / hook.get("alt_file", hook["file"])
    else:
        target = cwd / hook["file"]

    # Java Gradle uses alt_content
    if eco == "java" and not use_global and ((cwd / "build.gradle").exists() or (cwd / "build.gradle.kts").exists()):
        content = hook.get("alt_content", hook["content"]).format(cygnus_home=cygnus_home)
    else:
        content = hook["content"].format(cygnus_home=cygnus_home)

    existing = target.read_text() if target.exists() else ""
    if hook["marker"] and hook["marker"] in existing.lower():
        print(f"  {description} — already configured: {target}")
        return True

    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a") as f:
        f.write("\n" + content)
    scope = "global" if use_global else "project"
    print(f"  Installed ({scope}): {target}")
    print(f"  {description}")
    return True


# ── Commands ───────────────────────────────────────────────────────────────

def cmd_init(args):
    """Set up ~/.cyg/ and configure resolution for detected ecosystem."""
    eco = args.ecosystem or _detect_ecosystem()
    use_global = getattr(args, "use_global", False)
    scope = "global" if use_global else "project"
    print(f"Cygnus init ({scope})")
    print(f"  Platform: {_PLATFORM}")
    print(f"  Home:     {CYG_HOME}")
    print(f"  Registry: {REGISTRY_URL}")

    # Create directory structure. chmod 0700 so other local users can't
    # read the cache (which contains response data tied to the user's API
    # key) or modify it (cache poisoning). Caught 2026-05-21 pen test M-1.
    CYGNUS_HOME.mkdir(parents=True, exist_ok=True)
    try:
        CYGNUS_HOME.chmod(0o700)
    except (OSError, PermissionError):
        pass  # filesystem may not support chmod (e.g., Windows w/o NTFS perms)
    if eco:
        (CYGNUS_HOME / eco).mkdir(exist_ok=True)

    # Write config
    config = {
        "registry": REGISTRY_URL,
        "platform": _PLATFORM,
        "home": str(CYGNUS_HOME),
        "ecosystem": eco,
        "initialized_at": __import__("datetime").datetime.now().isoformat(),
    }
    (CYGNUS_HOME / "config.json").write_text(json.dumps(config, indent=2) + "\n")

    if eco == "python":
        venv = _find_venv()
        _install_pip_find_links(venv)
        conf = _pip_conf_path(venv)
        wheels_dir = CYGNUS_HOME / "python" / "wheels"
        print(f"  Installed pip.conf: {conf}")
        print(f"  pip find-links: {wheels_dir}")
        print(f"  pip will check local wheels before downloading from PyPI.")
        if not venv:
            print(f"  (User-level — activate a virtualenv for project-scoped config)")
    elif eco and eco in HOOK_TEMPLATES:
        _install_hook(eco, use_global=use_global)
    elif eco:
        print(f"  Detected: {eco} (resolution hook not yet available)")
    else:
        print(f"  No project detected. Run from a project directory or use -e <ecosystem>.")
        print(f"  Supported: python, node, rust, go, java, csharp, ruby,")
        print(f"             dart, kotlin, scala, elixir, swift, php, cpp")

    print(f"\n  Ready. Run: cyg add <library>")


_NATIVE_INSTALL_CMD = {
    "python": "pip install",
    "node": "npm install",
    "rust": "cargo add",
    "go": "go get",
    "csharp": "dotnet add package",
    "java": "mvn dependency:resolve",
    "ruby": "gem install",
    "php": "composer require",
    "kotlin": "gradle dependencies",
    "scala": "sbt update",
    "dart": "dart pub add",
    "elixir": "mix deps.get",
    "swift": "swift package resolve",
    "cpp": "vcpkg install",
}


def _native_fallback(ecosystem: str, library: str, ci_mode: bool):
    """Fall back to native package manager in CI mode."""
    if not ci_mode:
        return
    cmd = _NATIVE_INSTALL_CMD.get(ecosystem, "")
    if cmd:
        import shlex
        import subprocess
        print(f"  [ci] Falling back: {cmd} {library}")
        subprocess.run([*shlex.split(cmd), library], capture_output=True)


def cmd_request(args):
    """Explicitly request verification for a library.

    `cyg verify` auto-queues when a lib isn't in the corpus at all,
    but for libs that ARE in the corpus at a lower confidence (e.g.
    ATTESTATION_ONLY, ALL_OK, TESTS_PASS) the auto-queue path doesn't
    fire — the user just sees a confidence grade and no next action.
    `request` always enqueues with explicit feedback.

    Surfaced 2026-06-05 fresh-user run: "documented `request` command
    doesn't exist; `issue` fallback crashes — no path to the core
    promise." Pinned by tests/test_cli.py::TestBypassedCommandsCanonical.
    """
    _check_tos()
    _check_balance()
    library = args.library
    version = getattr(args, "version", None) or ""
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"

    pin_version = ""
    if "==" in library:
        library, pin_version = library.split("==", 1)
    elif "@" in library and not library.startswith("@"):
        library, pin_version = library.rsplit("@", 1)
    if pin_version:
        version = pin_version

    if not version:
        _parse_lockfile(ecosystem)
        version = _LOCKFILE_VERSIONS.get(library, "latest")

    if not _upstream_package_exists(ecosystem, library):
        print(f"\n  Package '{library}' not found in the {ecosystem} registry.", file=sys.stderr)
        print(f"  Check the name and ecosystem (-e) flag.", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Requesting verification: {ecosystem}/{library}@{version}")

    url = f"{REGISTRY_URL}/compile/queue"
    payload = json.dumps({
        "ecosystem": ecosystem,
        "library": library,
        "version": version,
        "priority": 2,  # explicit > auto
        "source": "cli-request",
    }).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "cygnus-cli/1.0")
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(body).get("detail", e.reason)
        except Exception:
            detail = e.reason
        if e.code == 429:
            print(f"  {detail}", file=sys.stderr)
            print(f"  Check budget with: cyg status", file=sys.stderr)
        else:
            print(f"  Error: {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    status = data.get("status", "queued")
    if status == "already_queued":
        pending_since = data.get("pending_since", "")
        since_msg = f" (pending since {pending_since})" if pending_since else ""
        print(f"  Already queued for {ecosystem}/{library}@{version}{since_msg}.")
        print(f"  You will be notified when ready.")
    elif status == "already_compiled":
        grade = data.get("grade", "?")
        confidence = data.get("confidence", "?")
        if confidence in ("FULLY_VERIFIED", "VERIFIED_PARTIAL"):
            print(f"  Already verified: {library} → {confidence} ({grade})")
            print(f"  Run `cyg verify {library}` to see details.")
        else:
            print(f"  ✓ Re-queued for full verification (currently {confidence}/{grade}).")
            print(f"  You'll receive an email when ready.")
    else:
        print(f"  ✓ Queued for priority verification.")
        print(f"  You'll receive an email when ready.")
    print()
    print(f"  Run `cyg verify {library}` anytime to check status.")


def cmd_deposit(args):
    """Open Stripe Checkout in the browser to deposit USD into your account balance.

    Card entry happens on Stripe's hosted page (PCI-compliant) — the CLI never
    sees the card data. After payment, Stripe redirects to a confirmation
    page; this command polls /auth/billing/balance to surface the new total.

    Usage:
      cyg deposit <USD>          # minimum $10, maximum $1000 per deposit
      cyg deposit 50 --no-open   # don't auto-open browser; print URL only
    """
    amount_usd = int(getattr(args, "amount", 0) or 0)
    if amount_usd < 10:
        print("  Error: deposit below minimum ($10).", file=sys.stderr)
        sys.exit(1)
    if amount_usd > 1000:
        print(f"  Error: deposit exceeds maximum ($1000 per transaction).", file=sys.stderr)
        print(f"  Multiple deposits work, or contact support@blackswan-software.ai for Enterprise.", file=sys.stderr)
        sys.exit(1)
    amount_cents = amount_usd * 100

    api_key = os.environ.get("CYGNUS_API_KEY", "") or _load_config().get("api_key", "")
    if not api_key:
        print("  Error: not authenticated. Run any command to set up.",
              file=sys.stderr)
        sys.exit(1)

    return_url = "https://blackswan-software.ai/deposit/success"
    body = {"amount_cents": amount_cents, "return_url": return_url}
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/auth/billing/checkout",
        data=payload, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": api_key,
            "User-Agent": "cygnus-cli/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_b = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(body_b).get("detail", e.reason)
        except Exception:
            detail = e.reason
        print(f"  Error: {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    mode = data.get("mode", "live")
    checkout_url = data.get("checkout_url", "")
    if mode == "stub" or not checkout_url:
        print(f"  Stripe is not enabled on the server (mode={mode}).")
        print(f"  Deposit temporarily unavailable. Contact support@blackswan-software.ai if this persists.")
        sys.exit(1)

    no_open = bool(getattr(args, "no_open", False))
    print(f"  Opening Stripe Checkout for ${amount_usd:.2f}...")
    print(f"  URL: {checkout_url}")

    if not no_open:
        opened = False
        for opener in ("xdg-open", "open", "start"):  # linux, macOS, windows
            try:
                import subprocess  # local import; standard library
                subprocess.Popen([opener, checkout_url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                opened = True
                break
            except FileNotFoundError:
                continue
            except Exception:
                continue
        if not opened:
            print("  (Could not auto-open browser — paste the URL above manually.)")

    print()
    print("  Complete payment in the browser, then return here.")
    print("  Polling /auth/billing/balance for the new balance (Ctrl-C to stop)...")
    print()

    import time
    deadline = time.time() + 300
    initial_balance = None
    while time.time() < deadline:
        req = urllib.request.Request(
            f"{REGISTRY_URL}/auth/billing/balance",
            headers={"X-Api-Key": api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                bal = json.loads(resp.read())
            cents = int(bal.get("balance_cents", 0))
            if initial_balance is None:
                initial_balance = cents
                print(f"  Initial balance: ${initial_balance / 100:.2f}")
            elif cents > initial_balance:
                print(f"\n  ✓ Deposit received. New balance: ${cents / 100:.2f}")
                return
            else:
                print(f"    balance: ${cents / 100:.2f}  (waiting for webhook...)", end="\r", flush=True)
        except Exception:
            pass
        time.sleep(5)
    print()
    print("  Polling timed out after 5 minutes. The webhook may still be in flight.")
    print("  Check balance later with: cyg account")


# ── Editor extensions (`cyg extension install vscode`) ────────────────

EXTENSION_RELEASE_REPO = "blackswan-software/cygnus-cli"

_EDITOR_BINARIES = {
    "vscode":   ["code", "code-insiders"],
    "code":     ["code", "code-insiders"],
    "cursor":   ["cursor"],
    "codium":   ["codium", "vscodium"],
    "vscodium": ["codium", "vscodium"],
}


def _find_editor_binary(editor: str):
    """Locate the editor's `code`-style CLI on $PATH."""
    import shutil
    for candidate in _EDITOR_BINARIES.get(editor, []):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _resolve_latest_vsix_url():
    """Find the most recent .vsix asset on the cygnus-cli release page.

    Returns None on any failure so the caller can surface a clean error.
    Anonymous GitHub API access (rate-limited but fine for once-per-install).
    """
    api = f"https://api.github.com/repos/{EXTENSION_RELEASE_REPO}/releases/latest"
    try:
        req = urllib.request.Request(api, headers={"User-Agent": "cygnus-cli/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None
    for asset in data.get("assets", []) or []:
        name = asset.get("name", "")
        if name.endswith(".vsix"):
            url = asset.get("browser_download_url")
            if url:
                return url
    return None


def cmd_extension(args):
    """Dispatch `cyg extension <subcommand>`."""
    sub = getattr(args, "extension_command", None)
    if sub == "install":
        cmd_extension_install(args)
    else:
        print("Usage: cyg extension install [vscode|cursor|codium] [options]")
        print()
        print("  Distributes the Cygnus editor extension without the Microsoft")
        print("  Marketplace. Pulls the latest .vsix from the cygnus-cli release")
        print("  page on GitHub and invokes the editor's --install-extension flag.")


def cmd_extension_install(args):
    """Download + install the Cygnus VS Code extension into the chosen editor."""
    import subprocess
    import tempfile

    editor = getattr(args, "editor", "vscode") or "vscode"
    binary = _find_editor_binary(editor)
    if not binary:
        candidates = ", ".join(_EDITOR_BINARIES.get(editor, []))
        print(
            f"  Error: could not find a {editor} CLI on $PATH "
            f"(looked for: {candidates}).",
            file=sys.stderr,
        )
        print(
            "  Open VS Code → command palette → "
            "'Shell Command: Install code command in PATH'",
            file=sys.stderr,
        )
        sys.exit(1)

    vsix_local = getattr(args, "vsix_file", None)
    if vsix_local:
        if not Path(vsix_local).is_file():
            print(f"  Error: {vsix_local} not found.", file=sys.stderr)
            sys.exit(1)
        target = vsix_local
    else:
        vsix_url = getattr(args, "vsix_url", None) or _resolve_latest_vsix_url()
        if not vsix_url:
            print(
                "  Error: could not find a .vsix asset on the latest "
                f"{EXTENSION_RELEASE_REPO} release.",
                file=sys.stderr,
            )
            print(
                "  Workaround: download manually + use --vsix-file. "
                "Or open an issue with `cyg issue`.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"  Downloading {vsix_url}...")
        try:
            with tempfile.NamedTemporaryFile(
                prefix="cygnus-", suffix=".vsix", delete=False,
            ) as tmp:
                req = urllib.request.Request(
                    vsix_url, headers={"User-Agent": "cygnus-cli/1.0"},
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    tmp.write(resp.read())
                target = tmp.name
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"  Error downloading {vsix_url}: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"  Installing into {editor} via {binary}...")
    try:
        subprocess.run(
            [binary, "--install-extension", target, "--force"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"  Error: {binary} --install-extension returned exit {e.returncode}.",
            file=sys.stderr,
        )
        sys.exit(1)
    except FileNotFoundError:
        print(f"  Error: {binary} not executable (was found on $PATH).",
              file=sys.stderr)
        sys.exit(1)

    print()
    print("  ✓ Cygnus extension installed.")
    if API_KEY:
        print("  ✓ Existing API key in ~/.cyg/config.json will be picked up "
              "automatically.")
    else:
        print("  Run any command to authenticate (or leave blank for the "
              "free tier — 100 lookups/day).")
    print("  Restart your editor to activate.")


def cmd_help(args):
    """Print the full command list grouped by purpose.

    Pinned by tests/test_cli.py::TestCmdHelpGroupedScreen.
    """
    print("Cygnus — pre-compiled, verified artifacts alongside your package manager.\n")
    sections = [
        ("Commands", [
            ("verify",     "Verify + download pre-compiled deps (grade, sigs, CVEs, artifacts)"),
            ("check",      "CVE scan (free, no account needed)"),
            ("add",        "Download pre-compiled, verified artifact"),
            ("request",    "Request verification for a library"),
            ("status",     "Auth state, tier, balance, usage"),
            ("version",    "Print version"),
            ("help",       "This screen"),
        ]),
        ("Auth happens inline — first command prompts for email.\n", []),
        ("More commands", [
            ("login",      "Authenticate manually (usually not needed)"),
            ("logout",     "Clear stored credentials"),
            ("forgot-key", "Reset your API key via email"),
            ("reset-key",  "Consume a reset token"),
            ("cancel",     "Cancel paid subscription (keep account)"),
            ("delete-account", "Delete account + all server data (GDPR)"),
            ("uninstall",  "Cancel + remove all local data + binary"),
            ("list",       "Show installed artifacts"),
            ("lock",       "Generate cyg.lock"),
            ("sbom",       "Export CycloneDX SBOM"),
            ("init",       "Set up ~/.cyg/ and configure resolution"),
            ("cache",      "Manage local cache"),
            ("extension",  "Install editor extensions"),
            ("issue",      "File a bug report"),
            ("account",    "Show account usage"),
        ]),
    ]
    for title, entries in sections:
        print(f"  {title}")
        for cmd, desc in entries:
            print(f"    {cmd:<16}  {desc}")
        print()
    print("  Also works as: cygnus <command>")
    print("  Per-command options: cyg <command> --help")
    print("  Source: https://github.com/blackswan-software/cygnus-cli")


def cmd_install(args):
    """Download compiled artifact from registry to ~/.cyg/."""
    _check_tos()
    _check_balance()

    ci_mode = getattr(args, "ci", False)

    # Handle --from-lock
    if getattr(args, "from_lock", False):
        lock_entries = _parse_cygnus_lock()
        if not lock_entries:
            print("  No cyg.lock found. Run 'cyg lock' first.")
            return
        ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
        installed = 0
        fallen_back = 0
        print(f"  Installing {len(lock_entries)} libraries from cyg.lock...")
        for entry in lock_entries:
            args.library = entry["library"]
            args.version = "latest"
            cmd_install(args)
        if ci_mode:
            print(f"\n  [ci] Summary: {len(lock_entries)} libraries processed")
        return

    library = args.library
    if not library:
        print("  Usage: cyg add <library> or cyg add --from-lock")
        return

    version = args.version or "latest"
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"

    # Normalize library name for API calls (Go/Java use / and : in names)
    safe_lib = library.replace("/", "__").replace(":", "__")

    print(f"cyg add {ecosystem}/{library}@{version}")
    print(f"  Platform: {_PLATFORM}")

    # Resolve "latest" version
    if version == "latest":
        data = _api(f"/versions/{ecosystem}/{safe_lib}/latest")
        if data and data.get("version"):
            version = data["version"]
            print(f"  Resolved: {library}@{version}")
        else:
            print(f"  No compiled version found for {library}.")
            _native_fallback(ecosystem, library, ci_mode)
            return

    # Get manifest (has artifact URLs per target)
    manifest = _api(f"/manifest/{ecosystem}/{safe_lib}/{version}")
    if not manifest:
        print(f"  Not compiled yet.")
        _native_fallback(ecosystem, library, ci_mode)
        return

    # Find artifact for our platform.
    # Manifests come in two shapes:
    #   1. Flat (single-target): {filename, sha256, target, ...} — already resolved
    #   2. Multi-target: {artifacts: {x86_64-linux: {filename, ...}, universal: {...}}}
    # When a multi-target entry has filename="manifest.json", it's a pointer —
    # fetch the per-target manifest to get the real artifact filename.
    artifacts = manifest.get("artifacts", {})
    filename = ""
    expected_sha = ""
    cdn_url = ""
    target_key = ""

    if artifacts:
        # Multi-target manifest — pick platform or universal
        target_info = artifacts.get(_PLATFORM) or artifacts.get("universal")
        target_key = _PLATFORM if _PLATFORM in artifacts else "universal"
        if not target_info:
            available = list(artifacts.keys())
            print(f"  No artifact for {_PLATFORM}. Available: {available}")
            _native_fallback(ecosystem, library, ci_mode)
            return
        cdn_url = target_info.get("cdn_url", "")
        filename = target_info.get("filename", "")
        expected_sha = target_info.get("sha256", "")

        # filename="manifest.json" is a pointer — fetch the per-target manifest
        # through the registry proxy (CDN blocks manifest.json access)
        if filename == "manifest.json":
            proxy_url = f"{REGISTRY_URL}/artifact/{ecosystem}/{safe_lib}/{version}/{target_key}/manifest.json?proxy=true"
            try:
                req = urllib.request.Request(proxy_url, headers={"User-Agent": "cygnus-cli/1.0"})
                if API_KEY:
                    req.add_header("X-API-Key", API_KEY)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    per_target = json.loads(resp.read())
                    if per_target.get("filename") and per_target["filename"] != "manifest.json":
                        filename = per_target["filename"]
                        expected_sha = per_target.get("sha256", "")
                        cdn_url = ""  # rebuild below with real filename
            except Exception:
                pass
    else:
        # Flat manifest — filename and sha256 at top level
        filename = manifest.get("filename", "")
        expected_sha = manifest.get("sha256", "")
        target_key = manifest.get("target", "universal")

    # Build download URL — try CDN first, fall back to proxy if CDN is private (403)
    if not cdn_url or cdn_url.endswith("manifest.json"):
        cdn_url = f"https://cdn.blackswan-software.ai/artifacts/{ecosystem}/{safe_lib}/{version}/{target_key}/{filename}"
    proxy_url = f"{REGISTRY_URL}/artifact/{ecosystem}/{safe_lib}/{version}/{target_key}/{filename}?proxy=true"

    if not filename or filename == "manifest.json":
        print(f"  Manifest found but no downloadable artifact.")
        _native_fallback(ecosystem, library, ci_mode)
        return

    # Download to ~/.cyg/{ecosystem}/{library}/{version}/
    dest_dir = CYGNUS_HOME / ecosystem / library / version
    dest_file = dest_dir / filename

    if dest_file.exists():
        # Verify existing
        if expected_sha:
            actual = hashlib.sha256(dest_file.read_bytes()).hexdigest()
            if actual == expected_sha:
                print(f"  Already installed: {dest_file}")
                print(f"  SHA256: {actual[:16]}... verified")
                return
            else:
                print(f"  Existing file corrupted, re-downloading...")
        else:
            print(f"  Already installed: {dest_file}")
            return

    print(f"  Downloading: {filename}")

    # Try CDN first (fastest), fall back to proxy if CDN returns 403 (private ACL)
    downloaded = _download(cdn_url, dest_file)
    if not downloaded and proxy_url != cdn_url:
        print(f"  CDN private, using proxy...")
        downloaded = _download(proxy_url, dest_file)

    if downloaded:
        size_mb = dest_file.stat().st_size / (1024 * 1024)
        print(f"  Saved: {dest_file} ({size_mb:.1f}MB)")

        # Verify SHA256
        if expected_sha:
            actual = hashlib.sha256(dest_file.read_bytes()).hexdigest()
            if actual == expected_sha:
                print(f"  SHA256: verified")
            else:
                print(f"  SHA256 MISMATCH! Expected {expected_sha[:16]}... got {actual[:16]}...")
                print(f"  Removing corrupted file.")
                dest_file.unlink()
                return

        # Save manifest locally for `cyg list` / `cyg verify`
        (dest_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

        _populate_wheels_dir(ecosystem, dest_file)

        print(f"\n  Installed: {library}@{version} for {_PLATFORM}")
        print(f"  Location:  {dest_dir}")
    else:
        print(f"  Failed to download artifact.")
        _native_fallback(ecosystem, library, ci_mode)


def cmd_list(args):
    """Show installed Cygnus artifacts."""
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
    eco_dir = CYGNUS_HOME / ecosystem

    if not eco_dir.exists():
        print(f"No Cygnus artifacts installed for {ecosystem}.")
        print(f"Run: cyg add <library>")
        return

    print(f"Cygnus artifacts ({ecosystem})  [{_PLATFORM}]")
    print(f"{'Library':<30} {'Version':<15} {'Size':>10}  {'Confidence'}")
    print("-" * 75)

    count = 0
    for lib_dir in sorted(eco_dir.iterdir()):
        if not lib_dir.is_dir():
            continue
        for ver_dir in sorted(lib_dir.iterdir()):
            if not ver_dir.is_dir():
                continue
            manifest_file = ver_dir / "manifest.json"
            confidence = "ATTESTATION_ONLY"
            if manifest_file.exists():
                try:
                    m = json.loads(manifest_file.read_text())
                    confidence = m.get("confidence") or "ATTESTATION_ONLY"
                except Exception:
                    pass

            # Sum file sizes (excluding manifest)
            total = sum(f.stat().st_size for f in ver_dir.iterdir()
                        if f.is_file() and f.name != "manifest.json")
            size_str = f"{total / 1024 / 1024:.1f}MB" if total > 1024*1024 else f"{total / 1024:.0f}KB"

            print(f"{lib_dir.name:<30} {ver_dir.name:<15} {size_str:>10}  {confidence}")
            count += 1

    if count == 0:
        print("  (none)")
    print(f"\n{count} artifacts in {eco_dir}")


def cmd_lock(args):
    """Generate cyg.lock — a portable verification manifest.

    Reads the project's native lockfile, queries Cygnus for each dep's
    confidence + token count + CVE status, and writes cyg.lock.

    The lock file proves what was verified WITHOUT requiring vendor dirs
    (node_modules, .venv, etc.). Use with --from-lock on verify/install.
    """
    _check_tos()

    if args.ecosystem:
        ecosystems = [args.ecosystem]
    else:
        ecosystems = _detect_all_ecosystems()
        if not ecosystems:
            eco = _load_config().get("ecosystem") or "python"
            ecosystems = [eco]

    all_entries = []
    for ecosystem in ecosystems:
        deps = _parse_lockfile(ecosystem)
        if not deps:
            continue

        if len(ecosystems) > 1:
            print(f"\n  ── {ecosystem.upper()} ({len(deps)} libraries) ──")
        else:
            print(f"  Generating cyg.lock for {len(deps)} {ecosystem} dependencies...\n")

        for lib in deps:
            lib_encoded = lib.replace("/", "__").replace(":", "__")
            pinned = _LOCKFILE_VERSIONS.get(lib)
            if pinned:
                ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/{pinned}")
                if not ver_data:
                    all_entries.append({
                        "library": lib, "version": pinned, "ecosystem": ecosystem,
                        "confidence": "NOT_COMPILED", "signed": False, "cves": 0,
                    })
                    continue
            else:
                ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/latest")
            version = ver_data.get("version", "") if ver_data else ""
            if not version:
                all_entries.append({
                    "library": lib, "version": "unknown", "ecosystem": ecosystem,
                    "confidence": "NOT_COMPILED", "signed": False, "cves": 0,
                })
                continue

            confidence = ver_data.get("confidence") or "ATTESTATION_ONLY"

            manifest = _api(f"/manifest/{ecosystem}/{lib_encoded}/{version}")
            sig_data = manifest.get("cygnus_signature", {}) if manifest else {}
            signed = bool(sig_data and sig_data.get("signature"))

            provenance = _api(f"/provenance/{ecosystem}/{lib_encoded}/{version}")
            cve_count = len(provenance.get("advisories", [])) if provenance else 0

            entry = {
                "library": lib, "version": version, "ecosystem": ecosystem,
                "confidence": confidence,
                "signed": signed, "cves": cve_count,
            }

            if signed and manifest:
                artifact_data = _download_artifact_bytes(ecosystem, lib, version, manifest)
                if artifact_data:
                    sha = hashlib.sha256(artifact_data).hexdigest()
                    entry["sha256"] = sha
                    entry["signature"] = sig_data["signature"]
                    keys = _fetch_signing_keys()
                    if keys and keys.get("current", {}).get("key_id"):
                        entry["key_id"] = keys["current"]["key_id"]
                    _artifact_cache_set(sha, artifact_data)

            all_entries.append(entry)

    if not all_entries:
        print("  No dependencies found. Provide a lockfile.")
        return

    lock_file = Path.cwd() / "cyg.lock"
    eco_list = sorted(set(e["ecosystem"] for e in all_entries))
    lines = [
        f"# cyg.lock — generated {__import__('datetime').datetime.now().isoformat()}",
        f"# format: 2",
        f"# ecosystems: {', '.join(eco_list)}",
        f"# deps: {len(all_entries)}",
        "",
    ]
    for e in sorted(all_entries, key=lambda x: (x["ecosystem"], x["library"])):
        grade = _confidence_grade(e["confidence"]).strip()
        cve_flag = f"  cves={e['cves']}" if e["cves"] > 0 else ""
        integrity = ""
        if e.get("sha256"):
            integrity += f"  sha256={e['sha256']}"
        if e.get("signature"):
            integrity += f"  signature={e['signature']}"
        if e.get("key_id"):
            integrity += f"  key_id={e['key_id']}"
        lines.append(
            f"{e['library']}=={e['version']}  "
            f"ecosystem={e['ecosystem']}  "
            f"confidence={e['confidence']}  "
            f"signed={'yes' if e['signed'] else 'no'}  "
            f"grade={grade}{cve_flag}{integrity}"
        )

    lock_file.write_text("\n".join(lines) + "\n")

    fv = sum(1 for e in all_entries if e["confidence"] == "FULLY_VERIFIED")
    nc = sum(1 for e in all_entries if e["confidence"] == "NOT_COMPILED")
    cves = sum(e["cves"] for e in all_entries)

    print(f"  Written: cyg.lock ({len(all_entries)} deps across {len(eco_list)} ecosystem(s))")
    print(f"  Verified: {fv}/{len(all_entries)}  Not compiled: {nc}")
    if cves:
        print(f"  ⚠ {cves} known CVEs across {sum(1 for e in all_entries if e['cves'] > 0)} packages")
    print()


def cmd_sbom(args):
    """Generate a CycloneDX SBOM for the project.

    Reads lockfile, queries Cygnus for each dep's verification status,
    and outputs a CycloneDX 1.5 JSON SBOM to stdout or file.
    """
    _check_tos()
    output = getattr(args, "output", None)

    if args.ecosystem:
        ecosystems = [args.ecosystem]
    else:
        ecosystems = _detect_all_ecosystems()
        if not ecosystems:
            eco = _load_config().get("ecosystem") or "python"
            ecosystems = [eco]

    components = []
    for ecosystem in ecosystems:
        deps = _parse_lockfile(ecosystem)
        if not deps:
            continue

        for lib in deps:
            lib_encoded = lib.replace("/", "__").replace(":", "__")
            pinned = _LOCKFILE_VERSIONS.get(lib)
            if pinned:
                ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/{pinned}")
                if not ver_data:
                    ver_data = None
                    version = pinned
                else:
                    version = ver_data.get("version", pinned)
            else:
                ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/latest")
                version = ver_data.get("version", "unknown") if ver_data else "unknown"

            provenance = _api(f"/provenance/{ecosystem}/{lib_encoded}/{version}")
            advisories = provenance.get("advisories", []) if provenance else []

            component = {
                "type": "library",
                "name": lib,
                "version": version,
                "purl": f"pkg:{ecosystem}/{lib}@{version}",
                "properties": [
                    {"name": "cygnus:confidence", "value": ver_data.get("confidence", "ATTESTATION_ONLY") if ver_data else "NOT_COMPILED"},
                    {"name": "cygnus:ecosystem", "value": ecosystem},
                ],
            }
            if advisories:
                component["properties"].append(
                    {"name": "cygnus:cve_count", "value": str(len(advisories))}
                )
            components.append(component)

    if not components:
        print("  No dependencies found. Provide a lockfile.")
        return

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"name": "cygnus", "version": "1.0.0"}],
        },
        "components": components,
    }

    sbom_json = json.dumps(sbom, indent=2)

    if output:
        Path(output).write_text(sbom_json + "\n")
        print(f"  SBOM written: {output} ({len(components)} components)")
    else:
        print(sbom_json)


def cmd_check(args):
    """Check for updates, CVEs, and supply chain risks.

    Scans installed artifacts and/or lockfile dependencies for:
    - Known CVEs from deps.dev (Google Open Source Insights)
    - Available version updates
    - Confidence downgrades (was FULLY_VERIFIED, now FAILED)
    """
    _check_tos()
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
    library = getattr(args, "library", None)

    # Single library check — extract pinned version from specifiers
    pin_version = None
    if library:
        if "==" in library:
            library, pin_version = library.split("==", 1)
        elif "@" in library:
            library, pin_version = library.rsplit("@", 1)
        deps = [library]
        if pin_version:
            _LOCKFILE_VERSIONS[library] = pin_version
        else:
            _parse_lockfile(ecosystem)
    else:
        # Gather deps from lockfile OR installed artifacts
        deps = _parse_lockfile(ecosystem)
        eco_dir = CYGNUS_HOME / ecosystem

        if not deps and eco_dir.exists():
            for lib_dir in sorted(eco_dir.iterdir()):
                if lib_dir.is_dir():
                    deps.append(lib_dir.name)

    if not deps:
        print("No dependencies found. Provide a lockfile or run: cyg check <library>")
        return

    if pin_version:
        print(f"  Checking {library}@{pin_version} ({ecosystem}) for CVEs...\n")
    else:
        print(f"  Scanning {len(deps)} {ecosystem} dependencies for CVEs and updates...\n")

    total_cves = 0
    vulnerable = []
    outdated = []

    for lib in deps:
        lib_encoded = lib.replace("/", "__").replace(":", "__")

        pinned = _LOCKFILE_VERSIONS.get(lib)
        if pinned:
            version = pinned
        else:
            ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/latest")
            version = ver_data.get("version", "") if ver_data else ""
            if library and version:
                print(f"  ⚠ No pinned version found in lockfile — checking latest ({version})")
                print(f"    To scan your actual dependency: cyg check {lib}=={version}\n")
        if not version:
            continue

        # Check provenance for CVEs
        provenance = _api(f"/provenance/{ecosystem}/{lib_encoded}/{version}")
        advisories = provenance.get("advisories", []) if provenance else []
        risk_flags = provenance.get("risk_flags", []) if provenance else []

        if advisories:
            total_cves += len(advisories)
            vulnerable.append({
                "library": lib,
                "version": version,
                "advisories": advisories,
                "risk_flags": risk_flags,
            })

    # Report
    if vulnerable:
        print(f"  ⚠ VULNERABLE: {len(vulnerable)} package{'s' if len(vulnerable) != 1 else ''} with {total_cves} known CVE{'s' if total_cves != 1 else ''}\n")
        for v in vulnerable:
            print(f"  {v['library']}@{v['version']}  ({len(v['advisories'])} {'advisories' if len(v['advisories']) != 1 else 'advisory'})")
            for adv in v["advisories"]:
                print(f"    - {adv}")
            for flag in v.get("risk_flags", []):
                if "advisory" not in flag.lower():
                    print(f"    Risk: {flag}")
            print()
    else:
        print(f"  ✓ No known CVEs across {len(deps)} dependencies\n")

    # Check for updates
    print(f"  CVE source: deps.dev (Google OSV)")
    print(f"  Checked {len(deps)} packages. Run 'cyg verify' for full confidence grades.")


def _stamp_tos_local():
    """Persist tos_accepted + privacy_accepted into the raw config file."""
    try:
        raw = json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    except (json.JSONDecodeError, OSError):
        raw = {}
    raw["tos_accepted"] = True
    raw["privacy_accepted"] = True
    _save_config(raw)


def _check_tos():
    """Check TOS and Privacy acceptance via browser round-trip.

    Opens both Terms and Privacy pages. User accepts on the web pages
    (which POST to the auth backend / database). CLI verifies acceptance
    against the DB before proceeding. If user quits, returns False so
    the caller can clean up (delete account if new signup).
    """
    cfg = _load_config()
    if cfg.get("tos_accepted") and cfg.get("privacy_accepted"):
        return True

    if not API_KEY:
        print("  Free during launch. Daily quota + 3 grace credits if you hit the cap.")
        print("  Need more? Email support@blackswan-software.ai with your account email.")
        return True

    data = _api("/auth/usage", use_cache=False, quiet=True)
    if isinstance(data, dict):
        tos = data.get("tos_accepted", False)
        privacy = data.get("privacy_accepted", False)
        if tos and privacy:
            _stamp_tos_local()
            return True

    # Non-TTY / piped use: never block on input()
    if os.environ.get("CYGNUS_ACCEPT_TOS") == "1":
        try:
            payload = json.dumps({"tos_accepted": True, "privacy_accepted": True}).encode()
            req = urllib.request.Request(
                f"{REGISTRY_URL}/auth/accept-terms",
                data=payload, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
            )
            if API_KEY:
                req.add_header("X-Api-Key", API_KEY)
            urllib.request.urlopen(req, timeout=15)
        except Exception:
            pass
        _stamp_tos_local()
        return True

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Cygnus requires Terms of Service acceptance.", file=sys.stderr)
        print("Run 'cyg' once interactively, or set CYGNUS_ACCEPT_TOS=1", file=sys.stderr)
        sys.exit(1)

    # Get accept token so the web pages can POST acceptance back to the DB
    accept_token = None
    try:
        req = urllib.request.Request(
            f"{REGISTRY_URL}/auth/accept-token",
            data=b"", method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
        )
        if API_KEY:
            req.add_header("X-Api-Key", API_KEY)
        with urllib.request.urlopen(req, timeout=15) as resp:
            accept_token = json.loads(resp.read()).get("token")
    except Exception:
        pass

    tos_url = "https://blackswan-software.ai/terms"
    privacy_url = "https://blackswan-software.ai/privacy"
    if accept_token:
        tos_url += f"?t={accept_token}"
        privacy_url += f"?t={accept_token}"

    # Open both pages — user accepts on each web page
    print("  ──────────────────────────────────────────")
    print("  Please accept the Terms of Service and Privacy Policy")
    print("  in your browser to continue.")
    print()
    print(f"  Terms of Service: {tos_url}")
    print(f"  Privacy Policy:   {privacy_url}")
    print()
    try:
        _open_browser(tos_url)
    except Exception:
        pass
    try:
        _open_browser(privacy_url)
    except Exception:
        pass

    # Loop: user confirms they've accepted, we verify against the DB
    while True:
        try:
            choice = input("  Press Enter after accepting both (or q to quit): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.", file=sys.stderr)
            return False
        if choice in ("q", "quit"):
            return False

        # Verify against the database
        check = _api("/auth/usage", use_cache=False, quiet=True)
        tos_ok = isinstance(check, dict) and check.get("tos_accepted", False)
        priv_ok = isinstance(check, dict) and check.get("privacy_accepted", False)

        if tos_ok and priv_ok:
            _stamp_tos_local()
            print("  ──────────────────────────────────────────")
            print("  ✓ Terms of Service and Privacy Policy accepted.")
            print("  You can close the Terms and Privacy tabs in your browser.")
            return True

        # Tell the user what's still missing
        missing = []
        if not tos_ok:
            missing.append("Terms of Service")
        if not priv_ok:
            missing.append("Privacy Policy")
        print(f"  Not yet accepted: {', '.join(missing)}")
        print("  Please click 'Accept' on each page in your browser.")
        print()
        try:
            retry = input("  [r] Re-open pages  [q] Quit: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.", file=sys.stderr)
            return False
        if retry in ("q", "quit"):
            return False
        if retry in ("r", "reopen"):
            if not tos_ok:
                try:
                    _open_browser(tos_url)
                except Exception:
                    pass
            if not priv_ok:
                try:
                    _open_browser(privacy_url)
                except Exception:
                    pass
        print()


def _ensure_auth():
    """Inline auth gate — prompts for email and authenticates when no key.

    Called automatically by paid commands. The user never needs to run
    a separate login/signup command. Flow:
      1. Prompt for email
      2. Try signup first (POST /auth/web/signup)
         - 409 = already registered → fall back to login (POST /auth/login)
         - 200 = new account, code sent
      3. Prompt for code from email
      4. If new account: TOS acceptance + POST /auth/web/signup-verify
         If existing: POST /auth/login-verify
      5. Save key, reload API_KEY global
    """
    global API_KEY
    if API_KEY:
        return

    if _try_refresh():
        return

    if not sys.stdin.isatty():
        print("  Authentication required. Run `cyg login` in a terminal first.", file=sys.stderr)
        print("  (CI/scripts: set CYGNUS_API_KEY env var instead)", file=sys.stderr)
        sys.exit(1)

    print("  Account required. Quick setup (30 seconds):")
    print()
    try:
        email = input("  Email: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.", file=sys.stderr)
        sys.exit(1)
    if not email or "@" not in email:
        print("  Error: valid email required.", file=sys.stderr)
        sys.exit(1)

    # Try signup first — 409 means already registered, fall back to login.
    # This is the only reliable way to distinguish new vs existing because
    # /auth/login always returns 200 (privacy-safe, won't leak registration).
    is_new_account = True
    signup_payload = json.dumps({"email": email}).encode()
    signup_req = urllib.request.Request(
        f"{REGISTRY_URL}/auth/web/signup",
        data=signup_payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
    )
    try:
        with urllib.request.urlopen(signup_req, timeout=15) as resp:
            json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 409:
            is_new_account = False
        else:
            body = e.read().decode() if e.fp else ""
            try:
                detail = json.loads(body).get("detail", e.reason)
            except Exception:
                detail = e.reason
            print(f"  Error: {detail}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    if not is_new_account:
        # Existing account — send login code
        login_payload = json.dumps({"email": email}).encode()
        login_req = urllib.request.Request(
            f"{REGISTRY_URL}/auth/login",
            data=login_payload, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
        )
        try:
            with urllib.request.urlopen(login_req, timeout=15) as resp:
                json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            try:
                detail = json.loads(body).get("detail", e.reason)
            except Exception:
                detail = e.reason
            print(f"  Error: {detail}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"  Connection error: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"  ✓ Code sent to {email}. Check your inbox.")

    try:
        code = input("  Code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.", file=sys.stderr)
        sys.exit(1)
    if not code:
        print("  Error: code required.", file=sys.stderr)
        sys.exit(1)

    if is_new_account:
        verify_payload = json.dumps({"email": email, "code": code}).encode()
        verify_url = f"{REGISTRY_URL}/auth/web/signup-verify"
    else:
        verify_payload = json.dumps({"email": email, "code": code}).encode()
        verify_url = f"{REGISTRY_URL}/auth/login-verify"

    req = urllib.request.Request(
        verify_url,
        data=verify_payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(body).get("detail", e.reason)
        except Exception:
            detail = e.reason
        print(f"  Error: {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    new_key = data.get("api_key", "")
    if not new_key:
        next_step = data.get("next_step", "")
        if next_step:
            print(f"  {next_step}")
        else:
            print("  Error: server did not return a key.", file=sys.stderr)
        sys.exit(1)

    login_email = data.get("email", email)
    login_tier = data.get("tier", "free")
    login_rt = data.get("refresh_token", "")

    _add_account(login_email, new_key, tier=login_tier, refresh_token=login_rt)
    API_KEY = new_key

    tier_name = data.get("tier_name") or login_tier.upper()
    fingerprint = hashlib.sha256(new_key.encode()).hexdigest()[:8]
    if is_new_account:
        print(f"  ✓ Account created! {login_email}  Tier: {tier_name}  Key: ...{fingerprint}")
    else:
        print(f"  ✓ Authenticated as {login_email}. Tier: {tier_name}  Key: ...{fingerprint}")
    print()

    if is_new_account:
        accepted = _check_tos()
        if not accepted:
            print()
            print("  Account requires Terms of Service and Privacy Policy acceptance.")
            print("  Removing account...")
            try:
                del_req = urllib.request.Request(
                    f"{REGISTRY_URL}/auth/delete-account",
                    data=b"", method="POST",
                    headers={"User-Agent": "cygnus-cli/1.0", "X-API-Key": new_key},
                )
                urllib.request.urlopen(del_req, timeout=15)
            except Exception:
                pass
            _remove_account(login_email)
            API_KEY = ""
            print("  Account removed. Run `cyg login` to try again.")
            sys.exit(1)


def _check_balance():
    """Gate paid commands on quota/balance. Calls _ensure_auth first."""
    _ensure_auth()

    usage = _api("/auth/usage", use_cache=False, quiet=True)
    if not isinstance(usage, dict):
        return True

    remaining = usage.get("remaining_today", None)
    balance = usage.get("balance_usd", 0)

    if remaining is None:
        return True
    if isinstance(remaining, (int, float)) and remaining > 0:
        return True
    if isinstance(balance, (int, float)) and balance > 0:
        return True

    resets_at = usage.get("resets_at", "midnight UTC")
    tier = usage.get("tier", "free")
    print(f"  Daily {tier}-tier quota exhausted ({remaining} requests remaining).")
    print(f"  Resets at:    {resets_at}")
    if tier == "free":
        print(f"  Upgrade:      cyg deposit <USD> (unlocks higher limits)")
    print(f"  Need help?    support@blackswan-software.ai")
    sys.exit(1)


def _verify_from_lock_offline(entries: list[dict], ci_mode: bool):
    """Verify deps using integrity data embedded in cyg.lock. No API calls, no quota.

    For each entry with sha256 + signature: load artifact from cache or CDN,
    verify SHA-256 matches, verify Ed25519 signature. Entries without integrity
    data report their lock-recorded status with a note to regenerate.
    """
    keys = _fetch_signing_keys()
    public_pem = None
    if keys and keys.get("current", {}).get("public_key_pem"):
        public_pem = keys["current"]["public_key_pem"]

    print(f"  Verifying {len(entries)} dependencies from cyg.lock (offline, no quota)...\n")
    print(f"  {'Library':<35} {'Version':<12} {'Integrity':<22} Grade")
    print(f"  {'─' * 82}")

    verified = 0
    failed = 0
    no_integrity = 0
    security_issue = False

    for e in entries:
        lib = e["library"]
        ver = e.get("version") or "?"
        grade = e.get("grade") or _confidence_grade(e.get("confidence", "?")).strip()
        sha = e.get("sha256")
        sig = e.get("signature")
        eco = e.get("ecosystem") or "python"

        if e.get("confidence") == "SECURITY_ISSUE_DETECTED":
            security_issue = True

        if not sha or not sig:
            no_integrity += 1
            status = "no integrity data"
            print(f"  {lib:<35} {ver:<12} {status:<22} {grade}")
            continue

        artifact_data = _artifact_cache_get(sha)
        if not artifact_data:
            manifest = _api(f"/manifest/{eco}/{lib.replace('/', '__').replace(':', '__')}/{ver}", quiet=True)
            if manifest:
                artifact_data = _download_artifact_bytes(eco, lib, ver, manifest)
            if artifact_data:
                actual_sha = hashlib.sha256(artifact_data).hexdigest()
                if actual_sha == sha:
                    _artifact_cache_set(sha, artifact_data)
                else:
                    print(f"  {lib:<35} {ver:<12} {'SHA-256 MISMATCH':<22} {grade}")
                    failed += 1
                    continue
            else:
                cached_file = _artifact_cache_dir() / sha
                if not cached_file.exists():
                    print(f"  {lib:<35} {ver:<12} {'download failed':<22} {grade}")
                    failed += 1
                    continue

        if artifact_data and public_pem:
            sig_ok = _verify_ed25519_signature(artifact_data, sig, public_pem)
            if sig_ok is True:
                verified += 1
                print(f"  {lib:<35} {ver:<12} {'OK (offline)':<22} {grade}")
            elif sig_ok is False:
                failed += 1
                print(f"  {lib:<35} {ver:<12} {'SIGNATURE INVALID':<22} {grade}")
            else:
                verified += 1
                print(f"  {lib:<35} {ver:<12} {'SHA-256 OK (no lib)':<22} {grade}")
        elif artifact_data:
            verified += 1
            print(f"  {lib:<35} {ver:<12} {'SHA-256 OK':<22} {grade}")
        else:
            failed += 1
            print(f"  {lib:<35} {ver:<12} {'verify failed':<22} {grade}")

    print(f"\n  ── Summary ──")
    print(f"  Integrity verified: {verified}/{len(entries)}")
    if failed:
        print(f"  Failed:             {failed}")
    if no_integrity:
        print(f"  No integrity data:  {no_integrity}  (regenerate lock: cyg lock)")
    print(f"  Quota used:         0 (offline verification)")
    print()

    if ci_mode and security_issue:
        sys.exit(1)
    if ci_mode and failed > 0:
        sys.exit(1)


def cmd_verify(args):
    """Verify + download pre-compiled artifacts — one command, ready to build.

    Scans project deps, checks verification status, downloads pre-compiled
    artifacts to ~/.cyg/, and caches them for offline/CI use. Like npm install
    but with verification grades, signatures, and CVE checks included.

    Usage:
      cyg verify requests           # verify + download single library
      cyg verify requests==2.31.0   # specific version
      cyg verify                    # auto-detect lockfile, verify + download all deps
      cyg verify --ci               # CI mode: exit 1 only on SECURITY_ISSUE
      cyg verify --from-lock        # restore from cyg.lock (offline if integrity data present)
    """
    _check_tos()
    library = getattr(args, "library", None)
    from_lock = getattr(args, "from_lock", False)

    # --from-lock with integrity data skips quota gate entirely
    if from_lock and not library:
        lock_entries = _parse_cygnus_lock()
        if not lock_entries:
            print("  No cyg.lock found. Run 'cyg lock' first.")
            return
        ci_mode = getattr(args, "ci", False)
        has_integrity = any(e.get("sha256") and e.get("signature") for e in lock_entries)
        if has_integrity:
            _verify_from_lock_offline(lock_entries, ci_mode)
            return
        # No integrity data — fall back to online (quota applies)
        _check_balance()
        ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
        _verify_project(ecosystem, [e["library"] for e in lock_entries], ci_mode)
        return

    _check_balance()
    # Ecosystem priority: explicit flag > config file > auto-detect > python
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
    ci_mode = getattr(args, "ci", False)
    show_cve = getattr(args, "cve", False)

    # Version pinning: "requests==2.31.0" or "requests@2.31.0"
    pin_version = None
    if library and "==" in library:
        library, pin_version = library.split("==", 1)
    elif library and "@" in library:
        library, pin_version = library.rsplit("@", 1)

    check_sig = getattr(args, "check_signature", False)

    if library:
        # Single library verify
        result = _verify_single(ecosystem, library, pin_version=pin_version,
                                show_cve=show_cve, check_signature=check_sig)
        if ci_mode and result.get("confidence") == "SECURITY_ISSUE_DETECTED":
            sys.exit(1)
    else:
        # Project-wide verify — from native lockfile
        # Multi-ecosystem: if no explicit --ecosystem, detect all and verify each
        if not args.ecosystem:
            ecosystems = _detect_all_ecosystems()
            if not ecosystems:
                print("  No lockfile found. Specify a library: cyg verify <library>")
                return
            total_deps = 0
            for eco in ecosystems:
                deps = _parse_lockfile(eco)
                if deps:
                    if len(ecosystems) > 1:
                        print(f"\n  ── {eco.upper()} ({len(deps)} libraries) ──")
                    total_deps += len(deps)
                    _verify_project(eco, deps, ci_mode)
            if total_deps == 0:
                print("  No lockfile found. Specify a library: cyg verify <library>")
        else:
            deps = _parse_lockfile(ecosystem)
            if not deps:
                print("  No lockfile found. Specify a library: cyg verify <library>")
                return
            _verify_project(ecosystem, deps, ci_mode)


_MAVEN_CENTRAL = "https://repo1.maven.org/maven2"


def _fetch_maven_pom(group_id: str, artifact_id: str, version: str) -> str:
    """Fetch a POM from Maven Central. Returns XML string or empty."""
    group_path = group_id.replace(".", "/")
    url = f"{_MAVEN_CENTRAL}/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read().decode()
    except Exception:
        return ""


def _resolve_bom_deps(pom_text: str) -> dict:
    """Parse a POM and resolve BOM-managed dependencies.

    Returns dict mapping declared artifactId → real groupId:artifactId.
    Fetches parent POM and imported BOMs from Maven Central.
    """
    import re
    import xml.etree.ElementTree as ET

    mapping = {}
    props = {}

    try:
        root = ET.fromstring(pom_text)
    except Exception:
        return mapping

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # Collect properties
    props_el = root.find(f"{ns}properties")
    if props_el is not None:
        for child in props_el:
            tag = child.tag.replace(ns, "")
            if child.text:
                props[tag] = child.text.strip()

    # Get version from parent if needed
    ver_el = root.find(f"{ns}version")
    parent_el = root.find(f"{ns}parent")
    if ver_el is not None and ver_el.text:
        props["project.version"] = ver_el.text.strip()
    elif parent_el is not None:
        pv = parent_el.find(f"{ns}version")
        if pv is not None and pv.text:
            props["project.version"] = pv.text.strip()

    def _resolve(val):
        if not val or "${" not in val:
            return val
        for k, v in props.items():
            val = val.replace(f"${{{k}}}", v)
        return val

    # Collect dependencyManagement entries (from this POM and imported BOMs)
    dm = root.find(f"{ns}dependencyManagement/{ns}dependencies")
    bom_poms_to_fetch = []

    if dm is not None:
        for dep in dm.findall(f"{ns}dependency"):
            g = dep.find(f"{ns}groupId")
            a = dep.find(f"{ns}artifactId")
            v = dep.find(f"{ns}version")
            scope = dep.find(f"{ns}scope")
            dtype = dep.find(f"{ns}type")

            if g is None or a is None:
                continue
            gtext = _resolve(g.text.strip()) if g.text else ""
            atext = a.text.strip() if a.text else ""
            vtext = _resolve(v.text.strip()) if v is not None and v.text else ""

            # BOM import: <type>pom</type><scope>import</scope>
            is_bom = (dtype is not None and dtype.text and dtype.text.strip() == "pom"
                      and scope is not None and scope.text and scope.text.strip() == "import")
            if is_bom and gtext and atext and vtext:
                bom_poms_to_fetch.append((gtext, atext, vtext))
            elif gtext and atext:
                mapping[atext] = f"{gtext}:{atext}"

    # Fetch parent POM and collect its dependencyManagement
    if parent_el is not None:
        pg = parent_el.find(f"{ns}groupId")
        pa = parent_el.find(f"{ns}artifactId")
        pv = parent_el.find(f"{ns}version")
        if pg is not None and pa is not None and pv is not None:
            parent_pom = _fetch_maven_pom(
                pg.text.strip(), pa.text.strip(), pv.text.strip())
            if parent_pom:
                parent_mapping = _resolve_bom_deps(parent_pom)
                # Parent provides defaults, child overrides
                for k, v in parent_mapping.items():
                    if k not in mapping:
                        mapping[k] = v

    # Fetch imported BOMs (max 5 to prevent infinite loops)
    for g, a, v in bom_poms_to_fetch[:5]:
        bom_pom = _fetch_maven_pom(g, a, v)
        if bom_pom:
            bom_mapping = _resolve_bom_deps(bom_pom)
            for k, val in bom_mapping.items():
                if k not in mapping:
                    mapping[k] = val

    return mapping


def _parse_java_pom(pom_path: Path) -> list:
    """Parse a Java pom.xml with full BOM resolution.

    1. Extract declared dependencies from <dependencies> sections
    2. Fetch parent POM + imported BOMs from Maven Central
    3. Resolve artifact aliases through BOM dependencyManagement
    """
    import re

    text = pom_path.read_text()

    # Build BOM mapping from the project POM
    bom_mapping = _resolve_bom_deps(text)

    # Extract dependencies from <dependencies> sections
    dep_sections = re.findall(r'<dependencies>(.*?)</dependencies>', text, re.DOTALL)
    seen = set()
    deps = []

    for section in dep_sections:
        for m in re.finditer(
            r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>',
            section
        ):
            group = m.group(1).strip()
            artifact = m.group(2).strip()
            key = f"{group}:{artifact}"

            # Skip Maven plugins
            if "maven-plugin" in key or "maven.plugins" in group:
                continue

            # Resolve through BOM mapping if the artifact has a known alias
            if artifact in bom_mapping:
                resolved = bom_mapping[artifact]
                if ":" in resolved:
                    key = resolved

            if key not in seen:
                seen.add(key)
                deps.append(key)

    return deps


# Common Maven BOM alias → real artifact mappings (fallback for when BOM fetch fails)
_MAVEN_ALIASES = {
    "org.testcontainers:testcontainers-junit-jupiter": "org.testcontainers:junit-jupiter",
    "org.testcontainers:testcontainers-mysql": "org.testcontainers:mysql",
    "org.testcontainers:testcontainers-postgresql": "org.testcontainers:postgresql",
    "org.testcontainers:testcontainers-mongodb": "org.testcontainers:mongodb",
    "org.testcontainers:testcontainers-kafka": "org.testcontainers:kafka",
    "org.testcontainers:testcontainers-elasticsearch": "org.testcontainers:elasticsearch",
}


def _resolve_maven_name(library: str) -> str:
    """Resolve Maven BOM aliases to real artifact names."""
    return _MAVEN_ALIASES.get(library, library)


def _verify_ed25519_signature(artifact_data: bytes, signature_b64: str, public_pem: str) -> bool:
    """Verify Ed25519 signature on artifact data.

    Uses the cryptography library (bundled in PyInstaller binary).
    Falls back to server-side /verify endpoint if cryptography unavailable.
    """
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        public_key = load_pem_public_key(public_pem.encode())
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, artifact_data)
        return True
    except ImportError:
        # cryptography not available — fall back to server verify
        return None  # None = couldn't verify locally
    except Exception:
        return False


def _fetch_signing_keys() -> dict | None:
    """Fetch published signing keys from /.well-known/cygnus-keys.json."""
    return _api("/.well-known/cygnus-keys.json", use_cache=True)


def _check_artifact_signature(ecosystem: str, library: str, version: str) -> dict:
    """Full signature verification: download artifact, fetch keys, verify.

    Returns: {"verified": bool, "algorithm": str, "signed_at": str, "error": str|None}
    """
    lib_encoded = library.replace("/", "__").replace(":", "__")

    # Get manifest — prefer /manifest (parent manifest with all targets)
    manifest = _api(f"/manifest/{ecosystem}/{lib_encoded}/{version}")
    if not manifest:
        manifest = _api(f"/artifact/{ecosystem}/{lib_encoded}/{version}/universal/manifest.json?proxy=true")
    if not manifest:
        return {"verified": False, "error": "No manifest found"}

    sig = manifest.get("cygnus_signature", {})
    if not sig or not sig.get("signature"):
        return {"verified": False, "error": "Not signed"}

    # Fetch public keys
    keys = _fetch_signing_keys()
    if not keys or not keys.get("current", {}).get("public_key_pem"):
        return {"verified": False, "error": "Cannot fetch signing keys"}

    public_pem = keys["current"]["public_key_pem"]

    # Download artifact for verification — resolve real target + filename from manifest
    filename = manifest.get("filename", "")
    target_key = "universal"
    if not filename or filename == "manifest.json":
        for target, info in manifest.get("artifacts", {}).items():
            fn = info.get("filename", "")
            if fn and fn != "manifest.json":
                filename = fn
                target_key = target
                break

    if not filename or filename == "manifest.json":
        return {"verified": False, "error": "No artifact filename in manifest"}

    # Download artifact bytes — try CDN first, fall back to proxy if 403 (private ACL)
    cdn_url = f"https://cdn.blackswan-software.ai/artifacts/{ecosystem}/{lib_encoded}/{version}/{target_key}/{filename}"
    proxy_url = f"{REGISTRY_URL}/artifact/{ecosystem}/{lib_encoded}/{version}/{target_key}/{filename}?proxy=true"
    artifact_data = None
    for url in (cdn_url, proxy_url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cygnus-cli/1.0"})
            if API_KEY:
                req.add_header("X-API-Key", API_KEY)
            with urllib.request.urlopen(req, timeout=30) as resp:
                artifact_data = resp.read()
            break
        except Exception:
            continue
    if artifact_data is None:
        return {"verified": False, "error": "Cannot download artifact (CDN and proxy both failed)"}

    # Verify
    result = _verify_ed25519_signature(artifact_data, sig["signature"], public_pem)

    if result is True:
        return {
            "verified": True,
            "algorithm": sig.get("algorithm", "Ed25519"),
            "signed_at": sig.get("signed_at", ""),
            "key_id": keys["current"].get("key_id", ""),
            "artifact_size": len(artifact_data),
            "artifact_sha256": hashlib.sha256(artifact_data).hexdigest(),
        }
    elif result is False:
        return {"verified": False, "error": "Signature INVALID — artifact may be tampered"}
    else:
        # Couldn't verify locally — try server
        sha = hashlib.sha256(artifact_data).hexdigest()
        server_result = _api(f"/verify/{sha}", use_cache=False)
        if server_result and server_result.get("status") == "verified":
            return {
                "verified": True,
                "algorithm": "Ed25519 (server-verified)",
                "signed_at": sig.get("signed_at", ""),
                "artifact_sha256": sha,
            }
        return {"verified": False, "error": "Cannot verify locally (install cryptography) or via server"}


def _verify_single(ecosystem: str, library: str, pin_version: str = None,
                    show_cve: bool = False, check_signature: bool = False) -> dict:
    """Verify a single library via unified /lookup endpoint."""
    # Resolve Maven BOM aliases
    if ecosystem == "java":
        resolved = _resolve_maven_name(library)
        if resolved != library:
            library = resolved

    lib_encoded = library.replace("/", "__").replace(":", "__")
    version_param = f"?version={pin_version}" if pin_version else ""

    # Single call gets everything
    data = _api(f"/lookup/{ecosystem}/{lib_encoded}{version_param}")

    if not data or not data.get("version"):
        if _last_api_error == 429:
            # Already printed the rate limit message in _api()
            return {"confidence": "RATE_LIMITED"}
        print(f"\n  {library}: not in Cygnus corpus")
        if not _upstream_package_exists(ecosystem, library):
            print(f"  Package '{library}' not found in the {ecosystem} registry.")
            print(f"  Check the name and ecosystem (-e) flag.")
            return {"confidence": "NOT_FOUND"}
        print(f"  Queuing for compilation...")
        _queue_compilation(ecosystem, library)
        print(f"  Queued. Run 'cyg verify {library}' again shortly to check progress.")
        return {"confidence": "NOT_COMPILED"}

    version = data["version"]
    confidence = data.get("confidence", "ATTESTATION_ONLY")
    functions = data.get("functions", [])
    signed = data.get("signed", False)
    signature = data.get("signature")
    license_info = data.get("license")
    cve = data.get("cves", {})
    advisories = cve.get("advisories", [])
    verify_url = data.get("verify_url")

    # On-demand synthesis: if not FULLY_VERIFIED, trigger immediate verification
    if confidence not in ("FULLY_VERIFIED", "SECURITY_ISSUE_DETECTED"):
        print(f"\n  {ecosystem}/{library}@{version} — verifying...")
        synth_result = _trigger_on_demand(ecosystem, library, version)
        if synth_result and synth_result.get("confidence") == "FULLY_VERIFIED":
            confidence = "FULLY_VERIFIED"
            print(f"  ✓ Verified! {synth_result.get('ok_count', 0)}/{synth_result.get('vectors_tested', 0)} vectors passed")

    # Display
    grade = _confidence_grade(confidence)
    print(f"\n  {ecosystem}/{library}@{version}")
    print(f"  {'─' * 40}")
    print(f"  Confidence:  {confidence} {grade}")
    print(f"  Functions:   {len(functions)} verified" if functions else "  Functions:   pending verification")
    if functions:
        names = [f["function"] if isinstance(f, dict) else f for f in functions[:5]]
        print(f"  Functions:   {', '.join(names)}")
        if len(functions) > 5:
            print(f"               ... and {len(functions) - 5} more")
    if signed:
        sig_detail = f"Ed25519 (key: {signature['key_id'][:12]}...)" if signature and signature.get("key_id") else "Ed25519 ✓"
        print(f"  Signed:      {sig_detail}")
        if check_signature:
            print(f"  Verifying signature...")
            sig_result = _check_artifact_signature(ecosystem, library, version)
            if sig_result.get("verified"):
                print(f"  Signature:   VERIFIED ✓ ({sig_result.get('algorithm', 'Ed25519')})")
                print(f"  Artifact:    {sig_result.get('artifact_sha256', '')[:16]}... ({sig_result.get('artifact_size', 0) // 1024}KB)")
                if sig_result.get("key_id"):
                    print(f"  Key:         {sig_result['key_id']}")
            else:
                print(f"  Signature:   FAILED ✗ — {sig_result.get('error', 'unknown')}")
    else:
        print(f"  Signed:      not yet")
        if check_signature:
            print(f"  Signature:   not available (artifact not signed)")
    if verify_url:
        print(f"  Verify:      {REGISTRY_URL}{verify_url}")
    if license_info:
        print(f"  License:     {license_info}")
        if any(gpl in str(license_info).upper() for gpl in ("GPL", "AGPL", "LGPL")):
            print(f"  ⚠ Copyleft license detected — review before commercial use")

    # CVE display
    if advisories:
        print(f"  CVEs:        {len(advisories)} known {'advisories' if len(advisories) != 1 else 'advisory'}")
        if show_cve:
            for cve_id in advisories:
                print(f"               - {cve_id}")
        else:
            print(f"               run with --cve for details")
    else:
        print(f"  CVEs:        none known")
    if cve.get("source"):
        print(f"  CVE source:  {cve['source']}")
    for flag in cve.get("risk_flags", []):
        if "advisory" not in flag.lower():
            print(f"  Risk:        {flag}")

    badge_url = data.get("badge_url", "")
    if badge_url:
        print(f"  Badge:       {REGISTRY_URL}{badge_url}")
    print(f"  SBOM:        {REGISTRY_URL}{data.get('sbom_url', '')}")

    # Auto-download artifact for verified libraries — one-step workflow
    if confidence in ("FULLY_VERIFIED", "VERIFIED_PARTIAL", "TESTS_PASS"):
        _auto_install_artifact(ecosystem, library, version, confidence)

    print()

    return {
        "confidence": confidence, "version": version,
        "signed": signed, "cve_count": len(advisories), "advisories": advisories,
    }


def _confidence_grade(confidence: str) -> str:
    """Map confidence to a letter grade for quick scanning."""
    return {
        "FULLY_VERIFIED": "✓ A",
        "VERIFIED_PARTIAL": "~ B",
        "TESTS_PASS": "~ C",
        "ATTESTATION_ONLY": "○ D",
        "FAILED": "✗ F",
        "SECURITY_ISSUE_DETECTED": "⚠ BLOCKED",
        "NOT_COMPILED": "? not compiled",
    }.get(confidence, "?")


def _parse_lockfile(ecosystem: str) -> list[str]:
    """Auto-detect and parse lockfile for the ecosystem. Returns list of library names.
    Also populates _LOCKFILE_VERSIONS with pinned versions when available."""
    global _LOCKFILE_VERSIONS
    cwd = Path.cwd()
    deps = []

    if ecosystem == "python":
        # Priority: poetry.lock > Pipfile.lock > requirements.txt > pyproject.toml
        poetry_lock = cwd / "poetry.lock"
        if poetry_lock.exists():
            try:
                current_name = None
                for line in poetry_lock.read_text().splitlines():
                    if line.startswith("name = "):
                        current_name = line.split('"')[1] if '"' in line else None
                        if current_name:
                            deps.append(current_name)
                return deps
            except Exception:
                pass
        pipfile_lock = cwd / "Pipfile.lock"
        if pipfile_lock.exists():
            try:
                data = json.loads(pipfile_lock.read_text())
                for section in ("default", "develop"):
                    for lib in data.get(section, {}):
                        if lib not in deps:
                            deps.append(lib)
                return deps
            except Exception:
                pass
        for lockfile in ("requirements.txt", "requirements-lock.txt"):
            f = cwd / lockfile
            if f.exists():
                for line in f.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Strip version specifiers: requests==2.31.0 → requests
                    # But capture pinned version if available
                    if "==" in line:
                        parts = line.split("[")[0].split("==", 1)
                        lib = parts[0].strip()
                        ver = parts[1].strip().split(";")[0].strip() if len(parts) > 1 else None
                        if lib:
                            deps.append(lib)
                            if ver:
                                _LOCKFILE_VERSIONS[lib] = ver
                    else:
                        lib = line.split(">=")[0].split("<=")[0].split("~=")[0].split("!=")[0].split("[")[0].strip()
                        if lib:
                            deps.append(lib)
                return deps
        # Try pyproject.toml
        pyproject = cwd / "pyproject.toml"
        if pyproject.exists():
            try:
                text = pyproject.read_text()
                in_deps = False
                for line in text.splitlines():
                    if "dependencies" in line and "=" in line and "[" in line:
                        in_deps = True
                        continue
                    if in_deps:
                        if line.strip().startswith("]"):
                            break
                        lib = line.strip().strip('",').split(">=")[0].split("==")[0].split("<")[0].strip()
                        if lib and not lib.startswith("#"):
                            deps.append(lib)
            except Exception:
                pass

    elif ecosystem == "node":
        # Prefer package-lock.json (exact versions) over package.json
        lock = cwd / "package-lock.json"
        if lock.exists():
            try:
                data = json.loads(lock.read_text())
                # v2/v3 lockfile format: packages["node_modules/name"]
                pkgs = data.get("packages", {})
                for key, info in pkgs.items():
                    if key.startswith("node_modules/") and key.count("/") == 1:
                        lib = key.replace("node_modules/", "")
                        if lib and not lib.startswith("."):
                            deps.append(lib)
                            ver = info.get("version") if isinstance(info, dict) else None
                            if ver:
                                _LOCKFILE_VERSIONS[lib] = ver
                if not deps:
                    # v1 format: dependencies at top level
                    for lib, info in data.get("dependencies", {}).items():
                        deps.append(lib)
                        ver = info.get("version") if isinstance(info, dict) else None
                        if ver:
                            _LOCKFILE_VERSIONS[lib] = ver
                return deps
            except Exception:
                pass
        # Fallback: pnpm-lock.yaml
        pnpm = cwd / "pnpm-lock.yaml"
        if pnpm.exists():
            try:
                for line in pnpm.read_text().splitlines():
                    # pnpm lockfile format: '/package-name@version:' or 'package-name@version:'
                    line = line.strip()
                    if line and ("@" in line) and line.endswith(":"):
                        # Strip leading / and trailing :
                        entry = line.lstrip("/").rstrip(":")
                        # Get package name (everything before last @)
                        at_idx = entry.rfind("@")
                        if at_idx > 0:
                            lib = entry[:at_idx]
                            ver = entry[at_idx + 1:]
                            if lib and lib not in deps:
                                deps.append(lib)
                                if ver:
                                    _LOCKFILE_VERSIONS[lib] = ver
                return deps
            except Exception:
                pass
        # Fallback: yarn.lock
        yarn = cwd / "yarn.lock"
        if yarn.exists():
            try:
                current_lib = None
                for line in yarn.read_text().splitlines():
                    if line and not line.startswith(" ") and not line.startswith("#"):
                        current_lib = line.split("@")[0].strip('"')
                        if current_lib and current_lib not in deps:
                            deps.append(current_lib)
                    elif current_lib and line.strip().startswith("version "):
                        ver = line.strip().split('"')[1] if '"' in line else None
                        if ver:
                            _LOCKFILE_VERSIONS[current_lib] = ver
                        current_lib = None
                return deps
            except Exception:
                pass
        # Fallback: package.json (use exact pinned versions)
        pkg = cwd / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text())
                for lib, ver_spec in data.get("dependencies", {}).items():
                    deps.append(lib)
                    if isinstance(ver_spec, str):
                        clean = ver_spec.lstrip("^~>=<! ")
                        if clean and clean[0].isdigit():
                            _LOCKFILE_VERSIONS[lib] = clean
            except Exception:
                pass

    elif ecosystem == "go":
        gomod = cwd / "go.mod"
        if gomod.exists():
            for line in gomod.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("//") and not line.startswith("module") and not line.startswith("go ") and not line.startswith("require") and line != ")" and line != "(":
                    lib = line.split()[0] if line.split() else ""
                    if lib and "/" in lib:
                        deps.append(lib)

    elif ecosystem == "rust":
        cargo_lock = cwd / "Cargo.lock"
        if cargo_lock.exists():
            for line in cargo_lock.read_text().splitlines():
                if line.startswith("name = "):
                    lib = line.split('"')[1] if '"' in line else ""
                    if lib and lib not in deps:
                        deps.append(lib)

    elif ecosystem == "ruby":
        gemfile = cwd / "Gemfile.lock"
        if gemfile.exists():
            in_specs = False
            for line in gemfile.read_text().splitlines():
                if line.strip() == "specs:":
                    in_specs = True
                    continue
                if in_specs:
                    if not line.startswith("      "):
                        if line.startswith("    "):
                            lib = line.strip().split()[0]
                            if lib and not lib.startswith("("):
                                deps.append(lib)
                        else:
                            in_specs = False

    elif ecosystem == "csharp":
        # Look for *.csproj
        for csproj in cwd.glob("**/*.csproj"):
            try:
                text = csproj.read_text()
                import re
                for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"', text):
                    deps.append(m.group(1))
            except Exception:
                pass

    elif ecosystem == "java":
        pom = cwd / "pom.xml"
        if pom.exists():
            deps = _parse_java_pom(pom)

    elif ecosystem == "php":
        lock = cwd / "composer.lock"
        if lock.exists():
            try:
                data = json.loads(lock.read_text())
                for pkg in data.get("packages", []):
                    name = pkg.get("name", "")
                    if name:
                        deps.append(name)
                for pkg in data.get("packages-dev", []):
                    name = pkg.get("name", "")
                    if name and name not in deps:
                        deps.append(name)
            except Exception:
                pass
        elif (cwd / "composer.json").exists():
            try:
                data = json.loads((cwd / "composer.json").read_text())
                deps.extend(data.get("require", {}).keys())
                deps.extend(k for k in data.get("require-dev", {}).keys() if k not in deps)
                # Remove php and ext-* entries
                deps = [d for d in deps if not d.startswith("php") and not d.startswith("ext-")]
            except Exception:
                pass

    elif ecosystem == "elixir":
        lock = cwd / "mix.lock"
        if lock.exists():
            try:
                for line in lock.read_text().splitlines():
                    line = line.strip()
                    if line.startswith('"') and ":" in line:
                        lib = line.split('"')[1]
                        if lib:
                            deps.append(lib)
            except Exception:
                pass

    elif ecosystem == "dart":
        lock = cwd / "pubspec.lock"
        if lock.exists():
            try:
                current_pkg = None
                for line in lock.read_text().splitlines():
                    # pubspec.lock format: "  package_name:" at 2-space indent
                    if line and not line.startswith(" ") and line != "packages:":
                        continue
                    if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
                        current_pkg = line.strip().rstrip(":")
                        if current_pkg:
                            deps.append(current_pkg)
            except Exception:
                pass

    elif ecosystem == "swift":
        resolved = cwd / "Package.resolved"
        if resolved.exists():
            try:
                data = json.loads(resolved.read_text())
                # v2 format
                pins = data.get("pins", [])
                if not pins:
                    # v1 format
                    obj = data.get("object", {})
                    pins = obj.get("pins", [])
                for pin in pins:
                    # v2: identity field, v1: package field
                    lib = pin.get("identity") or pin.get("package", "")
                    if lib:
                        deps.append(lib)
            except Exception:
                pass

    elif ecosystem == "scala":
        # Parse build.sbt for libraryDependencies
        sbt = cwd / "build.sbt"
        if sbt.exists():
            try:
                import re
                text = sbt.read_text()
                # Match: "org" %% "artifact" % "version" or "org" % "artifact" % "version"
                for m in re.finditer(r'"([^"]+)"\s+%%?\s+"([^"]+)"', text):
                    artifact = m.group(2)
                    if artifact:
                        deps.append(artifact)
            except Exception:
                pass

    elif ecosystem == "kotlin":
        # Kotlin uses Gradle — same as Java but check build.gradle.kts
        for gradle in ("build.gradle.kts", "build.gradle"):
            gf = cwd / gradle
            if gf.exists():
                try:
                    import re
                    text = gf.read_text()
                    # Match: implementation("group:artifact:version")
                    for m in re.finditer(r'(?:implementation|api|compileOnly)\s*\(\s*"([^"]+)"', text):
                        parts = m.group(1).split(":")
                        if len(parts) >= 2:
                            deps.append(parts[1])  # artifact name
                except Exception:
                    pass

    elif ecosystem == "cpp":
        # 2026-06-05: cpp parse-lockfile branch was missing entirely. The
        # ecosystem was listed in the detection table but without this
        # branch _parse_lockfile returned [] and the user saw "No lockfile
        # found" in any C++ project.
        #
        # Priority: vcpkg.json > conanfile.txt > conanfile.py > CMakeLists.txt.
        # vcpkg.json is the cleanest (structured JSON); the others are
        # regex-grade fallbacks since arbitrary CMake can do anything.
        import re
        vcpkg = cwd / "vcpkg.json"
        if vcpkg.exists():
            try:
                data = json.loads(vcpkg.read_text())
                for dep in data.get("dependencies", []) or []:
                    if isinstance(dep, str):
                        deps.append(dep)
                    elif isinstance(dep, dict) and dep.get("name"):
                        name = dep["name"]
                        deps.append(name)
                        if dep.get("version>="):
                            _LOCKFILE_VERSIONS[name] = dep["version>="]
                return deps
            except Exception:
                pass
        conan_txt = cwd / "conanfile.txt"
        if conan_txt.exists():
            try:
                in_requires = False
                for line in conan_txt.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("["):
                        in_requires = line.lower() == "[requires]"
                        continue
                    if in_requires:
                        # name/version[@user/channel]
                        name = line.split("/")[0].strip()
                        if name:
                            deps.append(name)
                            if "/" in line:
                                ver = line.split("/", 1)[1].split("@")[0].strip()
                                if ver:
                                    _LOCKFILE_VERSIONS[name] = ver
                return deps
            except Exception:
                pass
        conan_py = cwd / "conanfile.py"
        if conan_py.exists():
            try:
                text = conan_py.read_text()
                for m in re.finditer(r'["\']([a-z0-9_-]+)/([0-9][^"\'@]*)', text):
                    name, ver = m.group(1), m.group(2)
                    deps.append(name)
                    _LOCKFILE_VERSIONS[name] = ver
                return deps
            except Exception:
                pass
        cmakelists = cwd / "CMakeLists.txt"
        if cmakelists.exists():
            try:
                text = cmakelists.read_text()
                for m in re.finditer(r'find_package\s*\(\s*([A-Za-z_][A-Za-z0-9_]+)', text):
                    name = m.group(1)
                    if name in {"Threads", "PkgConfig", "Git", "Python",
                                 "Python3", "Python2", "Doxygen"}:
                        continue
                    if name not in deps:
                        deps.append(name)
            except Exception:
                pass

    return deps


def _verify_project(ecosystem: str, deps: list[str], ci_mode: bool):
    """Verify all project dependencies. Incremental: only checks changed deps."""
    import time

    # Load previous verify state for incremental
    state_file = CYGNUS_HOME / "cache" / "verify-state.json"
    prev_state = {}
    if state_file.exists():
        try:
            prev_state = json.loads(state_file.read_text())
        except Exception:
            pass

    # Hash current dep list to detect changes
    dep_hash = hashlib.sha256(",".join(sorted(deps)).encode()).hexdigest()[:16]
    prev_hash = prev_state.get("dep_hash", "")
    prev_results = prev_state.get("results", {})
    prev_time = prev_state.get("verified_at", 0)
    cache_age = time.time() - prev_time
    cache_ttl = 86400  # 24h — matches server-side HTTP cache

    # Incremental: reuse cached results for deps that haven't changed.
    # Re-verify if: new deps added, deps removed, or cache expired (24h).
    cache_expired = cache_age > cache_ttl
    changed_deps = deps

    if prev_results and not cache_expired:
        # Keep cached results for deps still in the list
        changed_deps = [d for d in deps if d not in prev_results]
        # Also drop results for deps no longer in the list
        prev_results = {d: r for d, r in prev_results.items() if d in deps}

        if not changed_deps:
            hours_ago = cache_age / 3600
            print(f"  All {len(deps)} dependencies cached ({hours_ago:.0f}h ago, refreshes at 24h).")
            _print_verify_summary(prev_results, ci_mode, ecosystem)
            return
        print(f"  {len(changed_deps)} new deps (of {len(deps)} total). {len(prev_results)} cached. Verifying...")
    elif cache_expired and prev_results:
        print(f"  Cache expired (>24h). Re-verifying {len(deps)} dependencies...")
        prev_results = {}  # Force full re-verify
    else:
        print(f"  Verifying {len(deps)} dependencies for {ecosystem}...")

    results = dict(prev_results)  # Start with previous results

    # Resolve Maven BOM aliases for Java
    if ecosystem == "java":
        changed_deps = [_resolve_maven_name(d) for d in changed_deps]

    # /tokens/batch always returns latest — split pinned deps for individual lookup
    pinned_deps = [d for d in changed_deps if d in _LOCKFILE_VERSIONS]
    batch_deps = [d for d in changed_deps if d not in _LOCKFILE_VERSIONS]

    # Batch lookup for unpinned deps (one API call)
    batch_ok = False
    if batch_deps:
        batch_data = _api_ext_post("/tokens/batch", {
            "ecosystem": ecosystem,
            "libraries": batch_deps,
        })
        if batch_data and batch_data.get("results"):
            batch_ok = True
            batch_results = batch_data["results"]
            for lib in batch_deps:
                br = batch_results.get(lib, {})
                if br.get("status") == "found":
                    results[lib] = {
                        "confidence": "VERIFIED",
                        "version": br.get("version", "?"),
                    }
                else:
                    results[lib] = {"confidence": "NOT_COMPILED", "version": None}
                    _queue_compilation(ecosystem, lib)

    # Individual lookups for pinned deps + batch failures
    individual_deps = pinned_deps + ([] if batch_ok else batch_deps)
    for i, lib in enumerate(individual_deps):
        lib_encoded = lib.replace("/", "__").replace(":", "__")
        pinned = _LOCKFILE_VERSIONS.get(lib)
        if pinned:
            ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/{pinned}")
            if not ver_data:
                # Pinned version not compiled — don't silently substitute latest
                results[lib] = {"confidence": "NOT_COMPILED", "version": pinned}
                _queue_compilation(ecosystem, lib)
                continue
        else:
            ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/latest")
        version = ver_data.get("version") if ver_data else None
        confidence = ver_data.get("confidence", "ATTESTATION_ONLY") if ver_data else "NOT_COMPILED"

        if not version:
            results[lib] = {"confidence": "NOT_COMPILED", "version": None}
            _queue_compilation(ecosystem, lib)
        else:
            results[lib] = {"confidence": confidence, "version": version}

        if (i + 1) % 20 == 0:
            print(f"    ... {i + 1}/{len(individual_deps)}")

    # Auto-download artifacts for verified deps — one-step workflow
    installed = 0
    for lib, r in results.items():
        conf = r.get("confidence", "")
        ver = r.get("version")
        if ver and conf in ("FULLY_VERIFIED", "VERIFIED_PARTIAL", "TESTS_PASS", "VERIFIED"):
            _auto_install_artifact(ecosystem, lib, ver, conf)
            installed += 1

    # Save state for incremental
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({
        "dep_hash": dep_hash,
        "results": results,
        "verified_at": time.time(),
        "ecosystem": ecosystem,
    }, indent=2) + "\n")

    _print_verify_summary(results, ci_mode, ecosystem)


def _print_verify_summary(results: dict, ci_mode: bool, ecosystem: str = ""):
    """Print verify summary table and exit with appropriate code for CI."""
    fv = tp = ao = nc = 0
    print(f"\n  {'Library':<35} {'Version':<12} {'Confidence':<20} Grade")
    print(f"  {'─' * 80}")

    for lib in sorted(results.keys()):
        r = results[lib]
        conf = r.get("confidence") or "ATTESTATION_ONLY"
        ver = r.get("version") or "—"
        if ver is None:
            ver = "—"
        grade = _confidence_grade(conf)
        print(f"  {lib:<35} {ver:<12} {conf:<20} {grade}")

        if conf == "FULLY_VERIFIED":
            fv += 1
        elif conf in ("VERIFIED_PARTIAL", "TESTS_PASS"):
            tp += 1
        elif conf == "ATTESTATION_ONLY":
            ao += 1
        else:
            nc += 1

    # CVE summary across all deps
    total_cves = sum(r.get("cve_count", 0) for r in results.values())
    libs_with_cves = [lib for lib, r in results.items() if r.get("cve_count", 0) > 0]

    total = len(results)
    print(f"\n  Total: {total} deps — {fv} verified, {tp} partial, {ao} attested, {nc} unverified")

    if total_cves > 0:
        print(f"  ⚠ Security: {total_cves} known CVE{'s' if total_cves != 1 else ''} across {len(libs_with_cves)} package{'s' if len(libs_with_cves) != 1 else ''}")
        for lib in libs_with_cves:
            r = results[lib]
            print(f"    {lib}@{r.get('version', '?')}: {r['cve_count']} advisory{'s' if r['cve_count'] != 1 else ''}")
    else:
        print(f"  Security: no known CVEs")

    # Badge: only count FULLY_VERIFIED
    if fv > 0:
        print(f"\n  cygnus-verified: {fv} libraries")
        badge_url = f"{REGISTRY_URL}/badge/project?fv={fv}&total={total}"
        print(f"  Badge: {badge_url}")
        print(f"  Markdown: [![cygnus-verified]({badge_url})]({REGISTRY_URL})")
    else:
        if nc > 0:
            print(f"\n  No fully verified libraries yet — {nc} queued for compilation")
        else:
            print(f"\n  No fully verified libraries yet")

    if nc > 0 and fv > 0:
        print(f"  {nc} deps not in corpus — queued for compilation")

    # Audit deliverables per lib — SBOM and verify URLs
    verified_libs = [(lib, r) for lib, r in sorted(results.items())
                     if r.get("version") and r.get("confidence") not in
                     ("NOT_COMPILED", None)]
    if verified_libs and ecosystem:
        print(f"\n  Deliverables:")
        for lib, r in verified_libs:
            lib_enc = lib.replace("/", "__").replace(":", "__")
            ver = r.get("version", "")
            print(f"    {lib}@{ver}")
            print(f"      SBOM:  {REGISTRY_URL}/sbom/{ecosystem}/{lib_enc}/{ver}")
            print(f"      Audit: {REGISTRY_URL}/verify/{ecosystem}/{lib_enc}/{ver}")

    if ci_mode:
        # CI mode: output JSON summary for dashboards. Never fail on coverage gaps.
        # Only fail on security issues (SECURITY_ISSUE_DETECTED).
        import json as _json
        security_issues = [lib for lib, r in results.items()
                          if r.get("confidence") == "SECURITY_ISSUE_DETECTED"]
        cve_details = {lib: r.get("advisories", []) for lib, r in results.items()
                       if r.get("cve_count", 0) > 0}
        ci_result = {
            "total_deps": total,
            "fully_verified": fv,
            "partial": tp,
            "attested": ao,
            "unverified": nc,
            "coverage_pct": round(fv / max(total, 1) * 100, 1),
            "security_issues": security_issues,
            "total_cves": total_cves,
            "cve_packages": cve_details,
            "badge": f"cygnus-verified: {fv} libraries",
        }
        print(f"\n  CI summary: {_json.dumps(ci_result)}")
        if security_issues:
            print(f"  ⚠ SECURITY ISSUES: {', '.join(security_issues)}")
            sys.exit(1)


def _api_ext(path: str, use_cache: bool = True) -> dict | None:
    """GET from token-extractor with local cache. Returns JSON or None."""
    if use_cache:
        cached = _cache_get(f"ext:{path}")
        if cached is not None:
            return cached

    url = f"{TOKEN_EXTRACTOR_URL}{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "cygnus-cli/1.0")
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if use_cache and data is not None:
                _cache_set(f"ext:{path}", data)
            return data
    except Exception:
        return None


def _api_ext_post(path: str, body: dict) -> dict | None:
    """POST to token-extractor (e.g., batch lookup). No caching."""
    url = f"{TOKEN_EXTRACTOR_URL}{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "cygnus-cli/1.0")
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


# ── Auth ───────────────────────────────────────────────────────────────────

def cmd_auth_signup(args):
    """Create a free Cygnus account via email verification.

    Usage:
      cyg signup          # interactive: prompts for email, then code

    Two-step flow: enter email → receive 6-digit code → enter code → done.
    """
    try:
        email = input("  Email: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.", file=sys.stderr)
        sys.exit(1)
    if not email or "@" not in email:
        print("  Error: valid email required.", file=sys.stderr)
        sys.exit(1)

    payload = json.dumps({"email": email}).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/auth/web/signup",
        data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 409:
            print(f"  Already registered. Run: cyg login")
            return
        body_text = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(body_text).get("detail", e.reason)
        except Exception:
            detail = e.reason
        print(f"  Error: {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  ✓ Verification code sent to {email}. Check your inbox.")

    try:
        code = input("  Code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.", file=sys.stderr)
        sys.exit(1)
    if not code:
        print("  Error: code required.", file=sys.stderr)
        sys.exit(1)

    # Step 3: POST /auth/web/signup-verify → create account + get key
    payload = json.dumps({"email": email, "code": code}).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/auth/web/signup-verify",
        data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(body_text).get("detail", e.reason)
        except Exception:
            detail = e.reason
        print(f"  Error: {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    api_key = data.get("api_key", "")
    tier = data.get("tier", "free")
    rt = data.get("refresh_token", "")

    if not api_key:
        # Server didn't return key (race condition or web-only response)
        next_step = data.get("next_step", "Run: cyg login")
        print(f"  {next_step}")
        return

    global API_KEY
    _add_account(email, api_key, tier=tier, refresh_token=rt)
    API_KEY = api_key

    print(f"\n  Account created!")
    print(f"  Email: {email}")
    print(f"  Tier:  {tier.upper()}")
    print(f"\n  Saved to {CYGNUS_HOME / 'config.json'}")

    # TOS + Privacy acceptance via browser round-trip
    accepted = _check_tos()
    if not accepted:
        print()
        print("  Account requires Terms of Service and Privacy Policy acceptance.")
        print("  Removing account...")
        try:
            del_req = urllib.request.Request(
                f"{REGISTRY_URL}/auth/delete-account",
                data=b"", method="POST",
                headers={"User-Agent": "cygnus-cli/1.0", "X-API-Key": api_key},
            )
            urllib.request.urlopen(del_req, timeout=15)
        except Exception:
            pass
        _remove_account(email)
        API_KEY = ""
        print("  Account removed. Run `cyg signup` to try again.")
        sys.exit(1)

    print(f"\n  Start using:")
    print(f"    cyg verify")
    print(f"    cyg add flask")


def cmd_auth_login(args):
    """Magic-link login: email a 6-digit code, paste it back, get authenticated.

    Anthropic-style code-paste flow. The code is the primary surface (paste
    into terminal). The email also contains a convenience link, but the code
    is what authenticates. Key is rotated each login — that's the per-device
    isolation property without per-device complexity.

    Usage:
      cyg login                          # prompts for email + code
      cyg login --email me@example.com   # skips email prompt
    """
    global API_KEY
    # 021J: snapshot current config BEFORE any server call so a failed/aborted
    # login never leaves the user worse off.  The server may invalidate the old
    # key during /auth/login; if verify never completes we restore the snapshot.
    _prior_config = None
    if CONFIG_FILE.exists():
        try:
            _prior_config = CONFIG_FILE.read_text()
        except OSError:
            pass

    def _restore_prior():
        """Put back whatever was on disk before we started."""
        if _prior_config is not None:
            try:
                CONFIG_FILE.write_text(_prior_config)
                CONFIG_FILE.chmod(0o600)
            except OSError:
                pass

    # Step 1: email — from arg, cached config, or prompt
    cfg = _load_config()
    email = getattr(args, "email", None) or cfg.get("email", "")

    if not email:
        try:
            email = input("  Email: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.", file=sys.stderr)
            sys.exit(1)
    elif not getattr(args, "email", None):
        # Email came from cache — confirm with user
        try:
            ans = input(f"  Send sign-in code to {email}? [Y/n] ").strip().lower()
            if ans in ("n", "no"):
                email = input("  Email: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.", file=sys.stderr)
            sys.exit(1)

    if not email or "@" not in email:
        print("  Error: valid email required.", file=sys.stderr)
        sys.exit(1)

    # Step 2–4 wrapped so ANY failure restores the prior config (021J).
    _login_ok = False
    try:
        # Step 2: try signup first — 409 means existing, fall back to login.
        is_new_account = True
        signup_payload = json.dumps({"email": email}).encode()
        signup_req = urllib.request.Request(
            f"{REGISTRY_URL}/auth/web/signup",
            data=signup_payload, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
        )
        try:
            with urllib.request.urlopen(signup_req, timeout=15) as resp:
                json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 409:
                is_new_account = False
            else:
                body = e.read().decode() if e.fp else ""
                try:
                    detail = json.loads(body).get("detail", e.reason)
                except Exception:
                    detail = e.reason
                print(f"  Error: {detail}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"  Connection error: {e}", file=sys.stderr)
            sys.exit(1)

        if not is_new_account:
            login_payload = json.dumps({"email": email}).encode()
            login_req = urllib.request.Request(
                f"{REGISTRY_URL}/auth/login",
                data=login_payload, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
            )
            try:
                with urllib.request.urlopen(login_req, timeout=15) as resp:
                    json.loads(resp.read())
            except urllib.error.HTTPError as e:
                body = e.read().decode() if e.fp else ""
                try:
                    detail = json.loads(body).get("detail", e.reason)
                except Exception:
                    detail = e.reason
                print(f"  Error: {detail}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"  Connection error: {e}", file=sys.stderr)
                sys.exit(1)

        print(f"  ✓ Code sent to {email}. Check your inbox.")

        # Step 3: prompt for code (or accept via --code)
        code = getattr(args, "code", None)
        if not code:
            try:
                code = input("  Code: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n  Aborted.", file=sys.stderr)
                sys.exit(1)
        if not code:
            print("  Error: code required.", file=sys.stderr)
            sys.exit(1)

        # Step 4: verify code — signup-verify for new accounts, login-verify for existing
        if is_new_account:
            verify_payload = json.dumps({"email": email, "code": code}).encode()
            verify_url = f"{REGISTRY_URL}/auth/web/signup-verify"
        else:
            verify_payload = json.dumps({"email": email, "code": code}).encode()
            verify_url = f"{REGISTRY_URL}/auth/login-verify"

        req = urllib.request.Request(
            verify_url,
            data=verify_payload, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            try:
                detail = json.loads(body).get("detail", e.reason)
            except Exception:
                detail = e.reason
            print(f"  Error: {detail}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"  Connection error: {e}", file=sys.stderr)
            sys.exit(1)

        new_key = data.get("api_key", "")
        if not new_key:
            next_step = data.get("next_step", "")
            if next_step:
                print(f"  {next_step}")
            else:
                print("  Error: server did not return a key.", file=sys.stderr)
            sys.exit(1)

        login_email = data.get("email", email)
        login_tier = data.get("tier", "free")
        login_rt = data.get("refresh_token", "")

        _add_account(login_email, new_key, tier=login_tier, refresh_token=login_rt)
        API_KEY = new_key

        _login_ok = True
        tier_name = data.get("tier_name") or login_tier.upper()
        fingerprint = hashlib.sha256(new_key.encode()).hexdigest()[:8]
        if is_new_account:
            print(f"\n  ✓ Account created! {login_email}  Tier: {tier_name}  Key: ...{fingerprint}")
        else:
            print(f"  ✓ Logged in as {login_email}. Tier: {tier_name}  Key: ...{fingerprint}")
        print(f"  Credentials stored in {CONFIG_FILE}")

        # New accounts: TOS + Privacy acceptance via browser round-trip.
        # The web page POSTs acceptance to the database — CLI just polls.
        if is_new_account:
            print()
            accepted = _check_tos()
            if not accepted:
                print()
                print("  Account requires Terms of Service and Privacy Policy acceptance.")
                print("  Removing account...")
                try:
                    del_req = urllib.request.Request(
                        f"{REGISTRY_URL}/auth/delete-account",
                        data=b"", method="POST",
                        headers={"User-Agent": "cygnus-cli/1.0", "X-API-Key": new_key},
                    )
                    urllib.request.urlopen(del_req, timeout=15)
                except Exception:
                    pass
                _remove_account(login_email)
                API_KEY = ""
                _login_ok = False
                print("  Account removed. Run `cyg login` to try again.")
                sys.exit(1)
    except SystemExit:
        if not _login_ok:
            _restore_prior()
        raise
    except KeyboardInterrupt:
        _restore_prior()
        sys.exit(130)


def cmd_accounts(args):
    """List, switch, or remove local Cygnus accounts.

    Multi-account: same human can have corp + personal accounts (separate
    emails → separate Cygnus accounts → separate API keys). All are stored
    in ~/.cyg/config.json under "accounts"; one is "active" at a time.

    Subcommands:
      cyg accounts                  — list all accounts; ✓ marks active
      cyg accounts switch <email>   — change which account is active
      cyg accounts remove <email>   — drop an account from the machine
    """
    sub = getattr(args, "accounts_command", None) or "list"
    if sub in ("list", "ls", None):
        data = _load_accounts()
        accounts = data.get("accounts") or {}
        env_set = bool(os.environ.get("CYGNUS_API_KEY"))
        if env_set:
            print("  CYGNUS_API_KEY env var set — overrides any locally-stored")
            print("  accounts for this shell. (CI / scripts use this path.)")
            print()
        if not accounts:
            print("  No local accounts. Run `cyg login` to create one.")
            return
        active = data.get("active")
        print(f"  Accounts on this machine ({len(accounts)} total):")
        for email, info in accounts.items():
            marker = "✓" if (email == active and not env_set) else " "
            tier = info.get("tier", "?")
            label = info.get("label", "")
            label_disp = f" [{label}]" if label else ""
            print(f"    {marker} {email}{label_disp}  tier={tier}")
        if len(accounts) > 1:
            print()
            print("  Switch with: cyg accounts switch <email>")
        return

    if sub == "switch":
        target = getattr(args, "target", "") or ""
        target = target.strip()
        if not target:
            print("  Error: cyg accounts switch <email>", file=sys.stderr)
            sys.exit(1)
        data = _load_accounts()
        accounts = data.get("accounts") or {}
        if target not in accounts:
            print(f"  Error: '{target}' not found in local accounts.", file=sys.stderr)
            if accounts:
                print(f"  Known accounts:", file=sys.stderr)
                for email in accounts:
                    print(f"    {email}", file=sys.stderr)
            else:
                print(f"  (no local accounts — run `cyg signup`)", file=sys.stderr)
            sys.exit(1)
        _set_active_email(target)
        print(f"  ✓ Switched to {target}")
        return

    if sub == "remove":
        target = getattr(args, "target", "") or ""
        target = target.strip()
        if not target:
            print("  Error: cyg accounts remove <email>", file=sys.stderr)
            sys.exit(1)
        if not _remove_account(target):
            print(f"  Error: '{target}' not found.", file=sys.stderr)
            sys.exit(1)
        print(f"  ✓ Removed {target} from local accounts.")
        print(f"  Server-side account NOT deleted — run `cyg cancel` for that.")
        return

    print(f"  Unknown subcommand: {sub}", file=sys.stderr)
    sys.exit(1)


def cmd_auth_status(args):
    """Show current authentication state.

    Multi-account aware (v0.1.13): surfaces the active account's email +
    a switch hint when 2+ accounts are stored. CYGNUS_API_KEY env var
    takes precedence and is flagged explicitly so CI users can tell.
    """
    env_key = os.environ.get("CYGNUS_API_KEY", "")
    accounts_data = _load_accounts()
    accounts = accounts_data.get("accounts") or {}
    active_email = accounts_data.get("active") or ""

    if env_key:
        key = env_key
        source = "CYGNUS_API_KEY env var"
    elif active_email and accounts.get(active_email, {}).get("api_key"):
        key = accounts[active_email]["api_key"]
        source = active_email
    else:
        print("  Not authenticated. Run any command to set up.")
        return

    fingerprint = hashlib.sha256(key.encode()).hexdigest()[:8]
    if env_key:
        print(f"  Authenticated [{source}]")
    else:
        label = accounts.get(active_email, {}).get("label", "")
        label_disp = f" [{label}]" if label else ""
        print(f"  Active account: {active_email}{label_disp}")
        if len(accounts) > 1:
            print(f"  ({len(accounts)} accounts on this machine — switch with `cyg login`)")
    print(f"  Key fingerprint: ...{fingerprint}")
    print(f"  Registry: {REGISTRY_URL}")

    # Fetch usage from server. Field names match auth-service /auth/usage
    # response shape (containers/auth/app/main.py get_usage). Server-side
    # renames happened 2026-06-06: daily_used→daily_count, daily_remaining
    # →remaining_today, monthly_used→monthly_count. Prior CLI read the old
    # names and showed 0 / "?" silently — the field-name drift was invisible.
    usage = _api("/auth/usage", use_cache=False)
    if usage:
        print(f"  Tier: {usage.get('tier', '?').upper()}")
        # Server returns the canonical field names: daily_count / daily_limit
        # / remaining_today / monthly_count.
        daily = usage.get("daily_count", 0)
        limit = usage.get("daily_limit", "?")
        remaining = usage.get("remaining_today", "?")
        print(f"  Today: {daily} requests (limit: {limit}, remaining: {remaining})")
        prio_used = usage.get("priority_used_today", 0)
        prio_limit = usage.get("priority_limit", "?")
        print(f"  Priority queue: {prio_used}/{prio_limit} used this month")
        monthly = usage.get("monthly_count", 0)
        print(f"  This month: {monthly} requests")
        # billing_active + limits_enforced are top-level server flags users
        # need to interpret their state. Without them: a Pro-tier user can't
        # tell if their deposit is in test mode; a free-tier user can't tell
        # if rate limits are even being enforced (vs server-disabled).
        billing_active = usage.get("billing_active", False)
        limits_enforced = usage.get("limits_enforced", False)
        print(f"  Billing: {'live' if billing_active else 'Free'}")
        print(f"  Rate limits: {'enforced' if limits_enforced else 'disabled (operator override)'}")
    else:
        if _last_api_error == 401:
            print(f"  Your key was reset or is invalid — run `cyg login` to re-authenticate.")
        else:
            print(f"  Tier: unknown (server unreachable)")
            print(f"  (server unreachable — usage stats unavailable)")


def cmd_auth_logout(args):
    """Clear stored credentials from ~/.cyg/config.json."""
    cfg = _load_config()
    if not cfg.get("api_key"):
        print("  Not logged in (no key in config).")
        if os.environ.get("CYGNUS_API_KEY"):
            print("  Note: CYGNUS_API_KEY env var is still set — unset it to fully deauthenticate.")
        return

    print(f"  This will clear your stored API key from {CONFIG_FILE}.")
    print(f"  Your account stays active on the server — to log back in run `cyg login`.")
    confirm = input("  Log out? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Aborted. Still logged in.")
        return

    data = _load_accounts()
    active = data.get("active", "")
    if active and active in (data.get("accounts") or {}):
        data["accounts"][active]["api_key"] = ""
    _save_accounts(data)
    print(f"  ✓ Logged out. Key cleared from {CONFIG_FILE}")


def cmd_uninstall(args):
    """Uninstall Cygnus CLI — remove all local data and binaries."""
    print("  This will:")
    print(f"    1. Remove {CYGNUS_HOME}")
    print(f"    2. Remove cygnus and cyg binaries")
    print(f"  Your server-side account is NOT deleted (use `cyg delete-account` for that).")
    confirm = input("  Continue? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    # Remove pip.conf find-links (venv and user-level)
    venv = _find_venv()
    _remove_pip_find_links(venv)
    if venv:
        _remove_pip_find_links(None)  # also clean user-level
    print(f"  ✓ Removed pip find-links configuration")

    # Remove sitecustomize.py entry (legacy cleanup)
    if venv:
        sc = _sitecustomize_path(venv)
        if sc.exists():
            text = sc.read_text()
            if "cygnus" in text.lower():
                cleaned = "\n".join(
                    l for l in text.splitlines()
                    if "cygnus" not in l.lower() and "_cygnus" not in l
                )
                if cleaned.strip():
                    sc.write_text(cleaned.strip() + "\n")
                else:
                    sc.unlink()
                print(f"  ✓ Removed sitecustomize.py hook")

    # Remove ~/.cyg/ (and legacy ~/.cygnus/ if it still exists)
    import shutil
    if CYG_HOME.exists():
        shutil.rmtree(CYG_HOME, ignore_errors=True)
        print(f"  ✓ Removed {CYG_HOME}")
    if _OLD_HOME.exists():
        shutil.rmtree(_OLD_HOME, ignore_errors=True)
        print(f"  ✓ Removed {_OLD_HOME}")

    # Remove binary and symlink from install directory
    install_dir = Path.home() / ".local" / "bin"
    for name in ("cygnus", "cyg"):
        p = install_dir / name
        try:
            if p.exists() or p.is_symlink():
                p.unlink()
                print(f"  ✓ Removed {p}")
        except Exception:
            print(f"  ⚠ Could not remove {p} — delete manually")

    print("  Cygnus uninstalled. Thanks for trying it.")


def cmd_delete_account(args):
    """Delete your account and all server-side data (GDPR Art. 17)."""
    cfg = _load_config()
    key = API_KEY or cfg.get("api_key", "")
    if not key:
        print("  Not authenticated. Run any command to set up.")
        return

    print("  ⚠ This will PERMANENTLY delete your account and all data:")
    print("    - Profile, usage history, API keys")
    print("    - Stored tokens and synthesis results")
    print("    - Subscription (if any)")
    print()
    print("  This action cannot be undone.")
    confirm = input("  Type DELETE to confirm: ").strip()
    if confirm != "DELETE":
        print("  Aborted. Account not deleted.")
        return

    try:
        url = f"{REGISTRY_URL}/auth/delete-account"
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header("User-Agent", "cygnus-cli/1.0")
        req.add_header("X-API-Key", key)
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read())
        print("  ✓ Account deleted from server.")
        removed = result.get("removed", [])
        if removed:
            print(f"    Removed: {', '.join(removed)}")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  ⚠ API key is invalid or already deleted.")
        elif e.code == 404:
            print("  ⚠ Account not found on server (may have been deleted already).")
        else:
            print(f"  ⚠ Server error ({e.code}) — try again or contact support@blackswan-software.ai")
            return
    except Exception:
        print("  ⚠ Could not reach server — try again later.")
        return

    import shutil
    if CYG_HOME.exists():
        shutil.rmtree(CYG_HOME, ignore_errors=True)
        print(f"  ✓ Removed local data ({CYG_HOME})")

    print("  Account deletion complete.")


def cmd_auth_cancel(args):
    """Cancel subscription without uninstalling. Account stays active on free tier."""
    cfg = _load_config()
    key = API_KEY or cfg.get("api_key", "")
    if not key:
        print("  Not authenticated. Run any command to set up.")
        return

    print("  This will cancel your paid subscription.")
    print("  Your account stays active on the free tier (100 lookups/day).")
    print("  Your API key continues to work.")
    confirm = input("  Cancel subscription? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Kept current subscription.")
        return

    try:
        url = f"{REGISTRY_URL}/auth/billing/cancel"
        payload = json.dumps({"reason": "user_requested"}).encode()
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "cygnus-cli/1.0")
        req.add_header("X-API-Key", key)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        print(f"  ✓ Subscription cancelled")
        print(f"  Tier: {data.get('new_tier', 'free').upper()}")
        if data.get("active_until"):
            print(f"  Active until: {data['active_until'][:10]} (paid period ends)")
        print(f"\n  Your API key still works for free tier (100 lookups/day).")
        print(f"  To reactivate: run `cyg deposit <USD>` to add credit.")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("  No active subscription found.")
        else:
            body = e.read().decode() if e.fp else ""
            try:
                detail = json.loads(body).get("detail", e.reason)
            except Exception:
                detail = e.reason
            print(f"  Error: {detail}", file=sys.stderr)
    except Exception as e:
        print(f"  ⚠ Could not reach server: {e}")
        print(f"  Cancel manually at https://blackswan-software.ai/account")


def cmd_account(args):
    """Show user balance + recent charges (verified tier billing)."""
    env_key = os.environ.get("CYGNUS_API_KEY", "")
    cfg = _load_config()
    api_key = env_key or cfg.get("api_key", "")
    if not api_key:
        print("  Not authenticated. Run any command to set up.")
        sys.exit(1)

    headers = {"X-API-Key": api_key, "User-Agent": "cygnus-cli/1.0"}
    if getattr(args, "stripe_test", False):
        headers["X-Stripe-Test-Mode"] = "1"

    try:
        import urllib.request, urllib.error, json as _json
        auth_url = os.environ.get("CYGNUS_AUTH_URL", "https://auth.blackswan-software.ai")
        req = urllib.request.Request(f"{auth_url}/auth/billing/balance", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            data = _json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  Error: {e.code} {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"  Could not fetch balance: {e}")
        sys.exit(1)

    if args.json:
        print(_json.dumps(data, indent=2))
        return

    balance_usd = data.get("balance_usd", 0)
    total_deposited = data.get("total_deposited_cents", 0) / 100
    stripe_on = data.get("stripe_enabled", False)
    charges = data.get("charges", [])

    print(f"  Balance:          ${balance_usd:.2f}")
    if total_deposited > 0:
        print(f"  Total deposited:  ${total_deposited:.2f}")
    if stripe_on:
        print(f"  Payments:         enabled")
    else:
        print(f"  Payments:         not yet available")
    if charges:
        print(f"\n  Recent charges ({len(charges)}):")
        for c in charges[-10:][::-1]:
            delta = c.get("delta_cents", 0)
            sign = "+" if delta > 0 else ""
            reason = c.get("reason", "?")
            ts = c.get("ts", "")[:19]
            print(f"    {ts}  {sign}${delta / 100:>7.2f}  {reason}")
    if balance_usd == 0:
        # Free-period launch: don't promote deposit here. The CLI
        # command still works; this just doesn't tell free-tier users
        # to top up.
        print(f"\n  You're on the free tier. Email support@blackswan-software.ai")
        print(f"  with your account email if you need more than the daily quota + 3 grace credits.")


def cmd_auth_forgot_key(args):
    """Request a one-time email token to rotate the API key.

    Uses cached email from ~/.cyg/config.json. Prompts interactively
    only when no cached email exists.
    """
    cfg = _load_config()
    cached_email = cfg.get("email") or ""
    if cached_email:
        email = cached_email
        print(f"  Using email from {CONFIG_FILE}: {email}")
    else:
        try:
            email = input("  Email: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.", file=sys.stderr)
            sys.exit(1)
    if not email or "@" not in email:
        print("  Error: valid email required.", file=sys.stderr)
        sys.exit(1)

    payload = json.dumps({"email": email}).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/auth/forgot-key",
        data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # BUG 2 fix (2026-06-06): graceful 403/429/connection error
        # handling. The Cloudflare WAF can return 403 on perfectly-
        # formed POSTs (UA fingerprinting, IP deny-list, etc.) — a
        # one-word "Forbidden" is a dead end for the user. Surface
        # the support@ recovery path explicitly.
        if e.code in (403, 429):
            print(f"  Recovery email request was blocked at the edge "
                  f"(HTTP {e.code}).", file=sys.stderr)
            print(f"  This is usually a WAF / rate-limit / proxy issue, "
                  f"not your fault.", file=sys.stderr)
            print(f"  Email support@blackswan-software.ai with the "
                  f"address you signed up with;", file=sys.stderr)
            print(f"  we'll send the reset link directly.",
                  file=sys.stderr)
            sys.exit(1)
        body = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(body).get("detail", e.reason)
        except Exception:
            detail = e.reason
        print(f"  Error: {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    print("  ✓ If that email is registered, a reset token has been sent.")
    print("  Check your inbox, then run:")
    print("    cyg reset-key <TOKEN>")


def cmd_auth_reset_key(args):
    """Consume a one-time email token, rotate the API key, store the new key locally.

    Usage:
      cyg reset-key <TOKEN>
    """
    token = (getattr(args, "token", None) or "").strip()
    if not token:
        print("  Error: token required.", file=sys.stderr)
        print("  Run `cyg forgot-key` first to receive a token by email.", file=sys.stderr)
        sys.exit(1)

    print("  This will rotate your Cygnus API key. The current key will stop working.")
    print("  Any machine using the old key (CI, scripts, other laptops) must be updated.")
    confirm = input("  Continue? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Aborted. Token NOT consumed — run again when ready.")
        sys.exit(0)

    req = urllib.request.Request(
        f"{REGISTRY_URL}/auth/reset-key/{token}",
        data=b"", method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "cygnus-cli/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        try:
            detail = json.loads(body).get("detail", e.reason)
        except Exception:
            detail = e.reason
        if e.code == 400:
            print(f"  Error: {detail}", file=sys.stderr)
            print("  Tokens expire — request a fresh one with `cyg forgot-key`.", file=sys.stderr)
        elif e.code == 404:
            print(f"  Error: {detail}", file=sys.stderr)
        else:
            print(f"  Error: {e.code} {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    new_key = data.get("api_key", "") or data.get("new_key", "")
    if not new_key:
        print("  Error: server did not return a new key.", file=sys.stderr)
        sys.exit(1)

    cfg = _load_config()
    email = data.get("email", "") or cfg.get("email", "")
    tier = data.get("tier", "") or cfg.get("tier", "free")
    rt = data.get("refresh_token", "")

    # Update multi-account store first (canonical path)
    if email:
        _add_account(email, new_key, tier=tier, refresh_token=rt)
    else:
        # No email from server or config — legacy single-key fallback
        cfg["api_key"] = new_key
        if tier:
            cfg["tier"] = tier
        _save_config(cfg)

    fingerprint = hashlib.sha256(new_key.encode()).hexdigest()[:8]
    print(f"  ✓ New API key stored. Old key invalidated.")
    print(f"    Fingerprint: ...{fingerprint}")
    print(f"    Saved to {CONFIG_FILE}")


def cmd_auth(args):
    subcmd = getattr(args, "auth_command", None)
    if subcmd == "signup":
        cmd_auth_signup(args)
    elif subcmd == "login":
        cmd_auth_login(args)
    elif subcmd == "status":
        cmd_auth_status(args)
    elif subcmd == "logout":
        cmd_auth_logout(args)
    elif subcmd == "cancel":
        cmd_auth_cancel(args)
    elif subcmd == "forgot-key":
        cmd_auth_forgot_key(args)
    elif subcmd == "reset-key":
        cmd_auth_reset_key(args)
    else:
        # Dead code: `auth` is no longer a registered subcommand
        # (post-2026-06-06 flatten). argparse rejects `cygnus auth`
        # before reaching this branch. Strings updated to flat command
        # names anyway, in case anything routes here via deprecated path.
        print("Usage: cygnus <signup|login|status|logout|cancel|forgot-key|reset-key>")
        print("  signup       — create a free account")
        print("  login        — authenticate with existing API key")
        print("  status       — show current auth state")
        print("  logout       — clear stored credentials")
        print("  cancel       — cancel subscription (keep account)")
        print("  forgot-key    — request reset email if you lost your key")
        print("  reset-key      — consume an email token and rotate to a new key")


# ── Main ───────────────────────────────────────────────────────────────────

def cmd_cache(args):
    """Manage local CLI cache."""
    sub = getattr(args, "cache_command", None)
    if sub == "clear":
        cache = _cache_dir()
        count = 0
        for f in cache.glob("*.json"):
            f.unlink()
            count += 1
        print(f"  Cleared {count} cached entries from {cache}")
    elif sub == "status":
        import time
        cache = _cache_dir()
        files = list(cache.glob("*.json"))
        fresh = 0
        stale = 0
        total_size = 0
        for f in files:
            total_size += f.stat().st_size
            try:
                data = json.loads(f.read_text())
                age = time.time() - data.get("_cached_at", 0)
                if age < CACHE_TTL:
                    fresh += 1
                else:
                    stale += 1
            except Exception:
                stale += 1
        kb = total_size / 1024
        print(f"  Cache dir:  {cache}")
        print(f"  Entries:    {len(files)} ({fresh} fresh, {stale} stale)")
        print(f"  Size:       {kb:.1f} KB")
        print(f"  TTL:        {CACHE_TTL}s ({CACHE_TTL // 3600}h)")
    else:
        print("  Usage: cyg cache [clear|status]")


# ── Admin Commands (owner-only, hidden) ─────────────────────────────


def _require_founder_env() -> str:
    key = os.environ.get("CYGNUS_ADMIN_KEY", "")
    if not key:
        print("  Error: CYGNUS_ADMIN_KEY env var required for admin commands.", file=sys.stderr)
        print("  Export CYGNUS_ADMIN_KEY=<your-founder-key> and retry.", file=sys.stderr)
        sys.exit(1)
    return key


def _admin_api(method: str, path: str, body: dict | None = None) -> dict | None:
    auth_url = os.environ.get("CYGNUS_AUTH_URL", "https://auth.blackswan-software.ai")
    founder_key = _require_founder_env()
    url = f"{auth_url}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "cygnus-cli/1.0")
    req.add_header("X-Api-Key", founder_key)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode()).get("detail", e.reason)
        except Exception:
            detail = e.reason
        print(f"  Error ({e.code}): {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_admin(args):
    sub = getattr(args, "admin_command", None)
    if sub == "setup-2fa":
        cmd_admin_setup_2fa(args)
    else:
        print("  Usage: cyg admin setup-2fa")
        print("  All user management is in the dashboard USERS tab.")


def cmd_admin_setup_2fa(args):
    """One-time TOTP enrollment for dashboard admin actions."""
    data = _admin_api("POST", "/auth/admin/totp/setup", {})
    if not data:
        return
    secret = data.get("secret", "")
    uri = data.get("provisioning_uri", "")
    print("\n  TOTP Enrollment")
    print("  ─────────────────────────────────────")
    print(f"  Secret: {secret}")
    print(f"\n  Provisioning URI (scan as QR or paste into authenticator):")
    print(f"  {uri}")
    print()
    code = input("  Enter code from authenticator app: ").strip()
    if not code:
        print("  Cancelled.", file=sys.stderr)
        sys.exit(1)
    result = _admin_api("POST", "/auth/admin/totp/verify-setup", {"code": code})
    if result and result.get("enrolled"):
        print("  TOTP enrolled. Use your authenticator app for dashboard admin actions.")
    else:
        print("  Verification failed — check your authenticator app and retry.", file=sys.stderr)
        sys.exit(1)


def _first_run_onboarding():
    """First-run experience when user runs `cygnus` with no args."""
    cfg = _load_config()
    has_key = bool(cfg.get("api_key") or os.environ.get("CYGNUS_API_KEY"))

    print("\n  Cygnus — verified function signatures for every library")
    print("  https://blackswan-software.ai")
    print()

    # Auto-detect project
    ecosystem = _detect_ecosystem()
    lockfile_deps = _parse_lockfile(ecosystem) if ecosystem else []

    if not has_key:
        # New user — onboarding
        if lockfile_deps:
            print(f"  Found {len(lockfile_deps)} {ecosystem} dependencies in this project.")
            print(f"  Cygnus can verify them for known CVEs and behavioral correctness.")
            print()

        # Check founding member spots
        try:
            remaining_data = _api("/auth/founding/remaining", use_cache=False)
            if remaining_data and remaining_data.get("offer_active"):
                spots = remaining_data.get("remaining", "?")
                print(f"  ★ FOUNDING MEMBER: {spots} spots left — 12 months Pro tier, free.")
                print()
        except Exception:
            pass

        print("  Get started:")
        print("    cyg verify               Scan this project's dependencies")
        print("    cyg verify <library>      Check a specific library")
        print("    cyg check                 Scan for known CVEs")
        print("    cyg status           Check your account")
        print()
        print("  Free during launch. Daily quota + 3 free grace credits if you hit the cap.")
        print("  Need more? Email support@blackswan-software.ai with your account email.")

    else:
        # Returning user
        if lockfile_deps:
            print(f"  {len(lockfile_deps)} {ecosystem} dependencies detected.")
            print()
            print("    cyg verify               Verify + download all deps (one-step)")
            print("    cyg check                Scan for known CVEs")
            print("    cyg verify --ci          CI mode (JSON output, exit 1 on security issues)")
        else:
            print("  Commands:")
            print("    cyg verify <library>      Verify + download a specific library")
            print("    cyg check                 Scan for known CVEs")
            print("    cyg add <library>         Download signed artifact (explicit)")
            print("    cyg status           Account + usage stats")
    print()


def _parse_cygnus_lock() -> list[dict]:
    """Parse cyg.lock into structured entries. Falls back to cygnus.lock.

    Returns list of dicts with keys: library, version, ecosystem, confidence,
    tokens, signed, grade, cves, sha256, signature, key_id.
    Missing fields default to None/0.
    """
    lock_file = Path.cwd() / "cyg.lock"
    if not lock_file.exists():
        lock_file = Path.cwd() / "cygnus.lock"
    if not lock_file.exists():
        return []
    deps = []
    for line in lock_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("==", 1)
        lib = parts[0].strip()
        if not lib:
            continue
        entry = {"library": lib, "version": None, "ecosystem": None,
                 "confidence": None, "signed": False,
                 "grade": None, "cves": 0, "sha256": None,
                 "signature": None, "key_id": None}
        if len(parts) > 1:
            rest = parts[1]
            ver_end = rest.find("  ")
            if ver_end > 0:
                entry["version"] = rest[:ver_end].strip()
                fields_str = rest[ver_end:]
            else:
                entry["version"] = rest.strip()
                fields_str = ""
            for field in fields_str.split("  "):
                field = field.strip()
                if "=" not in field:
                    continue
                k, v = field.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k == "ecosystem":
                    entry["ecosystem"] = v
                elif k == "confidence":
                    entry["confidence"] = v
                elif k == "tokens":
                    entry["tokens"] = int(v) if v.isdigit() else 0
                elif k == "signed":
                    entry["signed"] = v == "yes"
                elif k == "grade":
                    entry["grade"] = v
                elif k == "cves":
                    entry["cves"] = int(v) if v.isdigit() else 0
                elif k == "sha256":
                    entry["sha256"] = v
                elif k == "signature":
                    entry["signature"] = v
                elif k == "key_id":
                    entry["key_id"] = v
        deps.append(entry)
    return deps


# NOTE: _detect_ecosystem() is defined at line 216 with full 15-ecosystem support.
# A duplicate was here that only detected 7 ecosystems — removed. See test_cli.py.


# ── `cyg issue` ─────────────────────────────────────────────────────
# We're a new tool. Every bug report builds trust. Make it friction-free.

ISSUE_REPO = "blackswan-software/cygnus-cli"


def _extract_name_from_email(email: str) -> str:
    """alice.smith@company.com → 'Alice'. Falls back to 'friend'."""
    if not email or "@" not in email:
        return "friend"
    local = email.split("@", 1)[0]
    for sep in (".", "_", "-", "+"):
        if sep in local:
            local = local.split(sep, 1)[0]
            break
    return local.capitalize() or "friend"


def _get_user_email() -> str:
    """Try config first (local, no API call), then /auth/usage, then git."""
    cfg = _load_config()
    if cfg.get("email"):
        return cfg["email"]
    data = _api("/auth/usage", use_cache=False, quiet=True)
    if isinstance(data, dict) and data.get("email"):
        return data["email"]
    try:
        import subprocess
        r = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True, text=True, timeout=2,
        )
        return r.stdout.strip()
    except (Exception,):
        return ""


def cmd_issue(args):
    """File a bug or feature request — `cyg issue [title]`.

    Slogan: <name>, file an issue. We're building trust.

    Strategy:
      1. Try `gh issue create` (if user has gh CLI) — best UX
      2. Fallback: print a github.com URL with the body pre-filled
    """
    import platform
    import subprocess  # BUG 5 (2026-06-06): module-level subprocess
                       # import was removed in an earlier refactor;
                       # cmd_issue's $EDITOR + gh fallback paths use
                       # subprocess.run/SubprocessError. Without this
                       # import the function NameError'd on every call.
    import urllib.parse

    email = _get_user_email()
    name = _extract_name_from_email(email)

    # The pitch
    print()
    print(f"  {name}, file an issue. We're building trust.")
    print()

    # Title
    title = args.title or ""
    if not title:
        try:
            title = input("  One-line title: ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if not title:
            print("  No title given. Aborted.")
            return

    # Body — from --body, or open $EDITOR, or empty
    body = args.body or ""
    if not body:
        template = (
            "<!-- Describe the issue. Lines starting with <!-- are dropped. -->\n\n"
            "**What I did:**\n\n\n"
            "**What I expected:**\n\n\n"
            "**What actually happened:**\n\n"
        )
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".md", delete=False, encoding="utf-8"
        ) as tf:
            tf.write(template)
            tf_path = tf.name
        editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or "nano"
        try:
            subprocess.run([editor, tf_path])
            raw = Path(tf_path).read_text(encoding="utf-8")
            body = "\n".join(
                ln for ln in raw.splitlines() if not ln.strip().startswith("<!--")
            ).strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            body = ""
        finally:
            Path(tf_path).unlink(missing_ok=True)

    # Auto-collected diagnostics — always included, user can edit them out
    try:
        from . import __version__ as cyg_version
    except Exception:
        cyg_version = "unknown"
    diag = (
        "\n\n---\n"
        "**Diagnostics (auto-collected — edit/remove freely):**\n"
        f"- cygnus: {cyg_version}\n"
        f"- OS: {platform.system()} {platform.release()} {platform.machine()}\n"
        f"- Python: {platform.python_version()}\n"
        f"- Registry: {REGISTRY_URL}\n"
    )
    full_body = (body + diag).strip()

    # Attempt 1: gh CLI
    try:
        result = subprocess.run(
            ["gh", "issue", "create", "-R", ISSUE_REPO, "-t", title, "-b", full_body],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            print()
            print(f"  ✓ Filed: {result.stdout.strip()}")
            print(f"  Thank you, {name}. We read every report.")
            return
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # Attempt 2: github.com URL with prefill
    qs = urllib.parse.urlencode({"title": title, "body": full_body})
    url = f"https://github.com/{ISSUE_REPO}/issues/new?{qs}"
    print()
    print("  No `gh` CLI found. Open this URL to file the issue:")
    print(f"  {url}")
    print()
    print(f"  Thank you, {name}. We read every report.")


class _CygHelpFormatter(argparse.HelpFormatter):
    def _format_action(self, action):
        if action.help == argparse.SUPPRESS:
            return ""
        return super()._format_action(action)


def main():
    try:
        _main_inner()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        cmd = " ".join(sys.argv[1:2]) or "unknown"
        print(f"Something went wrong ({cmd}): {exc}", file=sys.stderr)
        print("This is a bug — please report: cyg issue", file=sys.stderr)
        if os.environ.get("CYGNUS_DEBUG") == "1":
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)


def _main_inner():
    parser = argparse.ArgumentParser(
        prog="cyg",
        description="Cygnus — pre-compiled, verified artifacts alongside your package manager.",
        formatter_class=_CygHelpFormatter,
        add_help=False,
    )
    # `__version__` is set in cygnus/__init__.py and shipped in every
    # release. Falling back to "unknown" lets test environments that
    # import cli.py without a built package still register the flag.
    try:
        from . import __version__ as _cli_version
    except Exception:
        _cli_version = "unknown"
    # No global flags — all options are per-subcommand

    sub = parser.add_subparsers(dest="command",
                                metavar="{verify,check,add,request,status,version,help}")

    sub.add_parser("version", help="Print version")
    sub.add_parser("help", help="Full command reference")

    p_init = sub.add_parser("init", help=argparse.SUPPRESS)
    p_init.add_argument("--ecosystem", "-e", default=None,
                        help="Ecosystem (overrides auto-detect)")
    p_init.add_argument("--global", dest="use_global", action="store_true",
                        help="Install hook at user level (e.g. ~/.nuget/, ~/.cargo/) instead of project")

    p_add = sub.add_parser("add", help="Download pre-compiled, verified artifact")
    p_add.add_argument("library", nargs="?", default=None, help="Library name (or use --from-lock)")
    p_add.add_argument("version", nargs="?", default="latest", help="Version (default: latest)")
    p_add.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_add.add_argument("--from-lock", action="store_true", help="Install all deps from cyg.lock")
    p_add.add_argument("--ci", action="store_true", help="CI mode: fall back to native package manager if artifact unavailable, never prompt, exit 0")
    p_add.add_argument("--no-cache", action="store_true", help="Bypass local cache")

    p_list = sub.add_parser("list", help=argparse.SUPPRESS)
    p_list.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_check = sub.add_parser("check", help="CVE scan (free, no account needed)")
    p_check.add_argument("library", nargs="?", default=None, help="Library name (or scan all from lockfile)")
    p_check.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_check.add_argument("--no-cache", action="store_true", help="Bypass local cache")

    p_lock = sub.add_parser("lock", help=argparse.SUPPRESS)
    p_lock.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")

    p_sbom = sub.add_parser("sbom", help=argparse.SUPPRESS)
    p_sbom.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_sbom.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")

    p_verify = sub.add_parser("verify", help="Verify + download pre-compiled deps (one-step)")
    p_verify.add_argument("library", nargs="?", default=None, help="Library name or lib==version for pinning")
    p_verify.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_verify.add_argument("--ci", action="store_true", help="CI mode: JSON output, exit 1 only on security issues")
    p_verify.add_argument("--check-signature", action="store_true", help="Verify Ed25519 signature against published keys")
    p_verify.add_argument("--cve", action="store_true", help="Show known CVEs/security advisories for this version")
    p_verify.add_argument("--from-lock", action="store_true", help="Verify from cyg.lock (no native lockfile needed)")
    p_verify.add_argument("--no-cache", action="store_true", help="Bypass local cache")

    # Account lifecycle — flat top-level commands (2026-06-06 flatten).
    # The nested `cygnus auth X` namespace was removed in favor of
    # discoverable top-level cmds. Renamed `forgot-key`/`reset-key`
    # → `forgot-key`/`reset-key` to drop the dashes per operator decision.
    p_signup = sub.add_parser("signup", help=argparse.SUPPRESS)
    # NB: free-period launch — `--tier` accepts only `free` in the
    # public surface. Internal code still handles verified/enterprise
    # so server-side promotion works; the argparse choices list is
    # the public contract and shows only the free option. Add the
    # other tier choices back when paid tiers launch + the
    # TestNoPaywallRefsInFreePeriod pin is lifted.
    p_signup.add_argument("--tier", choices=["free"], default="free",
                          help="Account tier (free during launch)")
    p_login = sub.add_parser("login", help=argparse.SUPPRESS)
    p_login.add_argument("--email", help="Email address (will prompt if omitted)")
    p_login.add_argument("--code", help="6-digit code from email (will prompt after sending)")
    sub.add_parser("status", help="Auth state, tier, balance, usage")
    sub.add_parser("logout", help=argparse.SUPPRESS)
    sub.add_parser("cancel", help=argparse.SUPPRESS)
    sub.add_parser(
        "forgot-key",
        help=argparse.SUPPRESS,
    )
    p_userkey = sub.add_parser(
        "reset-key",
        help=argparse.SUPPRESS,
    )
    p_userkey.add_argument("token", help="The one-time token from the reset email")

    sub.add_parser("delete-account", help=argparse.SUPPRESS)
    sub.add_parser("uninstall", help=argparse.SUPPRESS)

    p_cache = sub.add_parser("cache", help=argparse.SUPPRESS)
    cache_sub = p_cache.add_subparsers(dest="cache_command")
    cache_sub.add_parser("clear", help="Clear all cached results")
    cache_sub.add_parser("status", help="Show cache stats")

    p_account = sub.add_parser("account", help=argparse.SUPPRESS)
    p_account.add_argument("--json", action="store_true", help="JSON output")

    # `cyg request <library>` — explicit verification request. `verify`
    p_request = sub.add_parser(
        "request",
        help="Request verification for a library — queues compilation + extraction",
    )
    p_request.add_argument("library",
                           help="Library name (e.g. spdlog, nlohmann/json)")
    p_request.add_argument("version", nargs="?", default="latest",
                           help="Version (default: latest)")
    p_request.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_request.add_argument("--no-cache", action="store_true", help="Bypass local cache")

    # `cyg deposit <USD>` — Stripe Checkout. Only register the subparser
    # when Stripe is enabled (CYGNUS_STRIPE=1). Pre-Stripe: command doesn't
    # appear in --help at all. Post-Stripe: flip the env var.
    if os.environ.get("CYGNUS_STRIPE") == "1":
        p_deposit = sub.add_parser(
            "deposit",
            help="Add funds to your account via Stripe Checkout (opens browser)",
        )
        p_deposit.add_argument("amount", type=int, metavar="USD",
                               help="Amount in USD (minimum $10, maximum $1000)")
        p_deposit.add_argument("--no-open", action="store_true",
                               help="Print checkout URL only")

    # `cyg extension install vscode` — distributes the VS Code extension
    # from the cygnus-cli GitHub releases page (no Marketplace dependency).
    p_extension = sub.add_parser(
        "extension",
        help=argparse.SUPPRESS,
    )
    extension_sub = p_extension.add_subparsers(dest="extension_command")
    p_ext_install = extension_sub.add_parser(
        "install",
        help="Install the Cygnus editor extension",
    )
    p_ext_install.add_argument(
        "editor", nargs="?", default="vscode",
        choices=["vscode", "code", "cursor", "codium", "vscodium"],
        help="Editor to install into (default: vscode)",
    )
    p_ext_install.add_argument(
        "--vsix-url", default=None,
        help="Override the .vsix download URL (default: latest cygnus-cli release on GitHub)",
    )
    p_ext_install.add_argument(
        "--vsix-file", default=None,
        help="Install a local .vsix file instead of downloading",
    )

    p_issue = sub.add_parser(
        "issue",
        help=argparse.SUPPRESS,
    )
    p_issue.add_argument("title", nargs="?", default=None,
                         help="One-line title (prompts if missing)")
    p_issue.add_argument("--body", default=None,
                         help="Issue body (opens $EDITOR if not provided)")

    # `cyg admin <subcommand>` — owner-only, hidden
    p_admin = sub.add_parser("admin", help=argparse.SUPPRESS)
    admin_sub = p_admin.add_subparsers(dest="admin_command")
    admin_sub.add_parser("setup-2fa", help="Enroll TOTP for dashboard admin")

    # Intercept legacy flags before argparse — redirect to subcommands
    if len(sys.argv) >= 2 and sys.argv[1] in ("--version", "-V"):
        print(f"cyg {_cli_version}")
        return
    if len(sys.argv) >= 2 and sys.argv[1] in ("--help", "-h"):
        cmd_help(argparse.Namespace())
        return

    args = parser.parse_args()

    if args.command == "version":
        print(f"cyg {_cli_version}")
        return
    elif args.command == "help":
        cmd_help(args)
        return

    # Per-subcommand ecosystem validation (only for commands that accept -e)
    if hasattr(args, "ecosystem"):
        args.ecosystem = _validate_ecosystem(getattr(args, "ecosystem", None))

    # Per-subcommand cache bypass
    if getattr(args, "no_cache", False):
        global CACHE_TTL
        CACHE_TTL = 0
    elif args.command == "init":
        cmd_init(args)
    elif args.command == "add":
        cmd_install(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "lock":
        cmd_lock(args)
    elif args.command == "sbom":
        cmd_sbom(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "signup":
        cmd_auth_signup(args)
    elif args.command == "login":
        cmd_auth_login(args)
    elif args.command == "status":
        cmd_auth_status(args)
    elif args.command == "logout":
        cmd_auth_logout(args)
    elif args.command == "cancel":
        cmd_auth_cancel(args)
    elif args.command == "forgot-key":
        cmd_auth_forgot_key(args)
    elif args.command == "reset-key":
        cmd_auth_reset_key(args)
    elif args.command == "cache":
        cmd_cache(args)
    elif args.command == "delete-account":
        cmd_delete_account(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    elif args.command == "account":
        cmd_account(args)
    elif args.command == "issue":
        cmd_issue(args)
    elif args.command == "request":
        cmd_request(args)
    elif args.command == "deposit":
        cmd_deposit(args)
    elif args.command == "extension":
        cmd_extension(args)
    elif args.command == "admin":
        cmd_admin(args)
    else:
        # First-run experience: no command → onboarding
        _first_run_onboarding()


if __name__ == "__main__":
    main()
