#!/usr/bin/env python3
"""Cygnus CLI — install pre-compiled artifacts alongside your package manager.

Usage:
  cygnus init                    Set up ~/.cygnus/ and configure resolution
  cygnus install <lib> [ver]     Download compiled artifact for current platform
  cygnus list                    Show installed Cygnus artifacts vs native
  cygnus check                   Check for updates and CVEs
  cygnus verify <lib>            Show verification/confidence for installed lib

The native package manager always works. Cygnus sits alongside it:
  pip install numpy              ← works as always
  cygnus install numpy           ← adds compiled .so to ~/.cygnus/python/numpy/
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

# ── Config ─────────────────────────────────────────────────────────────────

CYGNUS_HOME = Path(os.environ.get("CYGNUS_HOME", Path.home() / ".cygnus"))


def _validate_registry_url(url: str) -> str:
    """Reject non-HTTPS registry URLs (except localhost/file).

    Why: CLI fetches signed artifacts + verified tokens from the registry.
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
    "php", "swift", "kotlin", "elixir", "zig", "cpp", "dart",
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
    """Load ~/.cygnus/config.json. Returns empty dict if missing or corrupt."""
    try:
        return json.loads(CONFIG_FILE.read_text()) if CONFIG_FILE.exists() else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_config(data: dict):
    """Write ~/.cygnus/config.json with owner-only permissions."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2) + "\n")
    CONFIG_FILE.chmod(0o600)


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


# Env var takes precedence over stored config
API_KEY = os.environ.get("CYGNUS_API_KEY", "") or _load_config().get("api_key", "")

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

# ── Helpers ────────────────────────────────────────────────────────────────

def _api(path: str, use_cache: bool = True) -> dict | None:
    """GET from registry API with local cache. Returns JSON or None on error.

    Cache hit → returns instantly (no API call, no rate limit impact).
    Cache miss → fetches from API, caches result for 24h.
    Sets _last_api_error to the HTTP status code on failure (None on success).
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
            data = json.loads(resp.read())
            if use_cache and data is not None:
                _cache_set(path, data)
            return data
    except urllib.error.HTTPError as e:
        _last_api_error = e.code
        if e.code == 404:
            return None
        if e.code == 429:
            retry_after = None
            try:
                retry_after = e.headers.get("Retry-After")
            except Exception:
                pass
            print(f"\n  Daily limit reached.", file=sys.stderr)
            if retry_after:
                print(f"  Resets in: {retry_after}s", file=sys.stderr)
            print(f"  Upgrade at: https://auth.blackswan-software.ai", file=sys.stderr)
            return None
        if e.code == 401:
            print(f"  Not authenticated. Run: cygnus auth login", file=sys.stderr)
            return None
        print(f"  API error: {e.code} {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
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
    if API_KEY:
        req.add_header("X-API-Key", API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


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
# Remove this file or delete ~/.cygnus/ to revert to native-only.
import sys, os
_cygnus = os.path.expanduser('~/.cygnus/python')
if os.path.isdir(_cygnus) and _cygnus not in sys.path:
    sys.path.insert(0, _cygnus)
"""

# Per-ecosystem resolution hook templates
# Each hook tells the native package manager to check ~/.cygnus/{eco}/ first.
HOOK_TEMPLATES = {
    "node": {
        "file": ".npmrc",
        "global_file": "~/.npmrc",
        "marker": "cygnus",
        "content": """\
# Cygnus: native addon override directory
# Native npm packages remain untouched — Cygnus compiled addons load first.
cygnus_addon_path={cygnus_home}/node
""",
        "description": "Node.js: project .npmrc",
        "global_description": "Node.js: user-level ~/.npmrc",
    },
    "rust": {
        "file": ".cargo/config.toml",
        "global_file": "~/.cargo/config.toml",
        "marker": "cygnus",
        "content": """\
# Cygnus: pre-compiled crate registry
# Native crates.io remains the fallback. Cygnus versions resolve first.
[source.cygnus]
directory = "{cygnus_home}/rust"

[source.crates-io]
replace-with = "cygnus"
""",
        "description": "Rust: project .cargo/config.toml",
        "global_description": "Rust: user-level ~/.cargo/config.toml",
    },
    "go": {
        "file": None,  # env vars, not a file
        "marker": None,
        "env": {
            "GOPROXY": "file://{cygnus_home}/go,https://proxy.golang.org,direct",
            "GOMODCACHE": "{cygnus_home}/go/cache",
        },
        "description": "Go: GOPROXY + GOMODCACHE env vars",
    },
    "java": {
        "file": ".mvn/settings.xml",
        "global_file": "~/.m2/settings.xml",
        "marker": "cygnus",
        "content": """\
<!-- Cygnus: pre-compiled Maven artifacts -->
<!-- Native Maven Central remains the fallback. -->
<settings>
  <mirrors>
    <mirror>
      <id>cygnus</id>
      <mirrorOf>central</mirrorOf>
      <url>file://{cygnus_home}/java</url>
    </mirror>
  </mirrors>
</settings>
""",
        "description": "Java (Maven): project .mvn/settings.xml",
        "global_description": "Java (Maven): user-level ~/.m2/settings.xml",
        "alt_file": "settings.gradle",
        "alt_content": """\
// Cygnus: pre-compiled Gradle artifacts
// Native repositories remain the fallback.
pluginManagement {{
    repositories {{
        maven {{ url = uri("file://{cygnus_home}/java") }}
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
<!-- Cygnus: pre-compiled NuGet packages -->
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
        "file": None,  # Gemfile modification
        "marker": "cygnus",
        "description": "Ruby: Gemfile source (manual — add `source 'file://~/.cygnus/ruby'` to Gemfile)",
    },
    "dart": {
        "file": "pubspec.yaml",
        "global_file": None,
        "marker": "cygnus",
        "content": """\
# Cygnus: pre-compiled Dart packages
# Native pub.dev remains the fallback.
dependency_overrides:
  # Cygnus compiled packages resolve from local cache
  # cygnus_path: {cygnus_home}/dart
""",
        "description": "Dart: pubspec.yaml dependency override",
    },
    "kotlin": {
        "file": ".mvn/settings.xml",
        "global_file": "~/.m2/settings.xml",
        "marker": "cygnus",
        "content": """\
<!-- Cygnus: pre-compiled Kotlin artifacts -->
<!-- Native Maven Central remains the fallback. -->
<settings>
  <mirrors>
    <mirror>
      <id>cygnus</id>
      <mirrorOf>central</mirrorOf>
      <url>file://{cygnus_home}/kotlin</url>
    </mirror>
  </mirrors>
</settings>
""",
        "description": "Kotlin: project .mvn/settings.xml",
        "global_description": "Kotlin: user-level ~/.m2/settings.xml",
        "alt_file": "settings.gradle.kts",
        "alt_content": """\
// Cygnus: pre-compiled Kotlin artifacts
pluginManagement {{
    repositories {{
        maven {{ url = uri("file://{cygnus_home}/kotlin") }}
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
// Cygnus: pre-compiled Scala artifacts
// Native resolvers remain the fallback.
resolvers += "cygnus" at "file://{cygnus_home}/scala"
""",
        "description": "Scala: project/cygnus.sbt resolver",
        "global_description": "Scala: user-level ~/.sbt/1.0/cygnus.sbt",
    },
    "elixir": {
        "file": None,
        "marker": "cygnus",
        "description": "Elixir: add `{:dep, path: \"~/.cygnus/elixir/dep\"}` overrides in mix.exs deps",
    },
    "swift": {
        "file": None,
        "marker": None,
        "env": {
            "SWIFT_PACKAGE_REGISTRY_URL": "file://{cygnus_home}/swift",
        },
        "description": "Swift: SWIFT_PACKAGE_REGISTRY_URL env var",
    },
    "php": {
        "file": "composer.json",
        "global_file": "~/.composer/config.json",
        "marker": "cygnus",
        "content": """\
{{
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
        "file": "conanfile.txt",
        "global_file": "~/.conan2/remotes.json",
        "marker": "cygnus",
        "content": """\
# Cygnus: pre-compiled C/C++ packages
# Add to [requires] section:
# cygnus_local_path = {cygnus_home}/cpp
""",
        "description": "C/C++: Conan local cache (manual — set CONAN_USER_HOME or add remote)",
        "global_description": "C/C++: user-level Conan remotes",
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
    if hook.get("env"):
        print(f"  {description}")
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
    """Set up ~/.cygnus/ and configure resolution for detected ecosystem."""
    eco = args.ecosystem or _detect_ecosystem()
    use_global = getattr(args, "use_global", False)
    scope = "global" if use_global else "project"
    print(f"Cygnus init ({scope})")
    print(f"  Platform: {_PLATFORM}")
    print(f"  Home:     {CYGNUS_HOME}")
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
        if venv:
            sc = _sitecustomize_path(venv)
            existing = sc.read_text() if sc.exists() else ""
            if "cygnus" not in existing.lower():
                with open(sc, "a") as f:
                    f.write("\n" + SITECUSTOMIZE_CONTENT)
                print(f"  Installed sitecustomize.py: {sc}")
            else:
                print(f"  sitecustomize.py already configured: {sc}")
            print(f"  Python resolution: ~/.cygnus/python/ prepended to sys.path")
        else:
            print(f"  No virtualenv found. Activate one first, or run:")
            print(f"    python -m venv .venv && source .venv/bin/activate && cygnus init")
    elif eco and eco in HOOK_TEMPLATES:
        _install_hook(eco, use_global=use_global)
    elif eco:
        print(f"  Detected: {eco} (resolution hook not yet available)")
    else:
        print(f"  No project detected. Run from a project directory or use -e <ecosystem>.")
        print(f"  Supported: python, node, rust, go, java, csharp, ruby,")
        print(f"             dart, kotlin, scala, elixir, swift, php, cpp")

    print(f"\n  Ready. Run: cygnus install <library>")


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
        import subprocess
        full_cmd = f"{cmd} {library}"
        print(f"  [ci] Falling back: {full_cmd}")
        subprocess.run(full_cmd, shell=True, capture_output=True)


def cmd_install(args):
    """Download compiled artifact from registry to ~/.cygnus/."""
    _check_tos()

    ci_mode = getattr(args, "ci", False)

    # Handle --from-lock
    if getattr(args, "from_lock", False):
        deps = _parse_cygnus_lock()
        if not deps:
            print("  No cygnus.lock found. Run 'cygnus lock' first.")
            return
        ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
        installed = 0
        fallen_back = 0
        print(f"  Installing {len(deps)} libraries from cygnus.lock...")
        for lib in deps:
            args.library = lib
            args.version = "latest"
            cmd_install(args)
        if ci_mode:
            print(f"\n  [ci] Summary: {len(deps)} libraries processed")
        return

    library = args.library
    if not library:
        print("  Usage: cygnus install <library> or cygnus install --from-lock")
        return

    version = args.version or "latest"
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"

    # Normalize library name for API calls (Go/Java use / and : in names)
    safe_lib = library.replace("/", "__").replace(":", "__")

    # Prompt signup if no API key (first-time user)
    if not API_KEY and not ci_mode:
        print("  Tip: Run 'cygnus auth signup' for a free account (the daily quota)")
        print("       See pricing page for full tokens + artifacts (pay-as-you-go, no subscription)")
        print()

    print(f"cygnus install {ecosystem}/{library}@{version}")
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
        cdn_url = f"https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/artifacts/{ecosystem}/{safe_lib}/{version}/{target_key}/{filename}"
    proxy_url = f"{REGISTRY_URL}/artifact/{ecosystem}/{safe_lib}/{version}/{target_key}/{filename}?proxy=true"

    if not filename or filename == "manifest.json":
        print(f"  Manifest found but no downloadable artifact.")
        _native_fallback(ecosystem, library, ci_mode)
        return

    # Download to ~/.cygnus/{ecosystem}/{library}/{version}/
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

        # Save manifest locally for `cygnus list` / `cygnus verify`
        (dest_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

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
        print(f"Run: cygnus install <library>")
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
    """Generate cygnus.lock — a portable verification manifest.

    Reads the project's native lockfile, queries Cygnus for each dep's
    confidence + token count + CVE status, and writes cygnus.lock.

    The lock file proves what was verified WITHOUT requiring vendor dirs
    (node_modules, .venv, etc.). Use with --from-lock on verify/install.
    """
    _check_tos()
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
    deps = _parse_lockfile(ecosystem)

    if not deps:
        print(f"  No {ecosystem} dependencies found. Provide a lockfile.")
        return

    print(f"  Generating cygnus.lock for {len(deps)} {ecosystem} dependencies...\n")

    lock_entries = []
    for lib in deps:
        lib_encoded = lib.replace("/", "__").replace(":", "__")
        ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/latest")
        version = ver_data.get("version", "") if ver_data else ""
        if not version:
            lock_entries.append({
                "library": lib, "version": "unknown", "ecosystem": ecosystem,
                "confidence": "NOT_COMPILED", "tokens": 0, "signed": False, "cves": 0,
            })
            continue

        token_data = _api_ext(f"/tokens/{ecosystem}/{lib}/{version}")
        token_count = token_data.get("token_count", 0) if token_data else 0
        confidence = ver_data.get("confidence") or "ATTESTATION_ONLY"

        manifest = _api(f"/manifest/{ecosystem}/{lib_encoded}/{version}")
        signed = bool(manifest.get("cygnus_signature")) if manifest else False

        provenance = _api(f"/provenance/{ecosystem}/{lib_encoded}/{version}")
        cve_count = len(provenance.get("advisories", [])) if provenance else 0

        lock_entries.append({
            "library": lib, "version": version, "ecosystem": ecosystem,
            "confidence": confidence, "tokens": token_count,
            "signed": signed, "cves": cve_count,
        })

    # Write cygnus.lock
    lock_file = Path.cwd() / "cygnus.lock"
    lines = [
        f"# cygnus.lock — generated {__import__('datetime').datetime.now().isoformat()}",
        f"# ecosystem: {ecosystem}",
        f"# deps: {len(lock_entries)}",
        "",
    ]
    for e in sorted(lock_entries, key=lambda x: x["library"]):
        grade = _confidence_grade(e["confidence"]).strip()
        cve_flag = f" cves={e['cves']}" if e["cves"] > 0 else ""
        lines.append(
            f"{e['library']}=={e['version']}  "
            f"confidence={e['confidence']}  tokens={e['tokens']}  "
            f"signed={'yes' if e['signed'] else 'no'}  "
            f"grade={grade}{cve_flag}"
        )

    lock_file.write_text("\n".join(lines) + "\n")

    fv = sum(1 for e in lock_entries if e["confidence"] == "FULLY_VERIFIED")
    nc = sum(1 for e in lock_entries if e["confidence"] == "NOT_COMPILED")
    cves = sum(e["cves"] for e in lock_entries)

    print(f"  Written: cygnus.lock ({len(lock_entries)} deps)")
    print(f"  Verified: {fv}/{len(lock_entries)}  Not compiled: {nc}")
    if cves:
        print(f"  ⚠ {cves} known CVEs across {sum(1 for e in lock_entries if e['cves'] > 0)} packages")
    print()


def cmd_sbom(args):
    """Generate a CycloneDX SBOM for the project.

    Reads lockfile, queries Cygnus for each dep's verification status,
    and outputs a CycloneDX 1.5 JSON SBOM to stdout or file.
    """
    _check_tos()
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
    output = getattr(args, "output", None)
    deps = _parse_lockfile(ecosystem)

    if not deps:
        print("  No dependencies found. Provide a lockfile.")
        return

    components = []
    for lib in deps:
        lib_encoded = lib.replace("/", "__").replace(":", "__")
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

    # Single library check
    if library:
        deps = [library]
    else:
        # Gather deps from lockfile OR installed artifacts
        deps = _parse_lockfile(ecosystem)
        eco_dir = CYGNUS_HOME / ecosystem

        if not deps and eco_dir.exists():
            for lib_dir in sorted(eco_dir.iterdir()):
                if lib_dir.is_dir():
                    deps.append(lib_dir.name)

    if not deps:
        print("No dependencies found. Provide a lockfile or run: cygnus check <library>")
        return

    print(f"  Scanning {len(deps)} {ecosystem} dependencies for CVEs and updates...\n")

    total_cves = 0
    vulnerable = []
    outdated = []

    for lib in deps:
        lib_encoded = lib.replace("/", "__").replace(":", "__")

        # Get latest compiled version
        ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/latest")
        version = ver_data.get("version", "") if ver_data else ""
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
            print(f"  {v['library']}@{v['version']}  ({len(v['advisories'])} advisory{'s' if len(v['advisories']) != 1 else ''})")
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
    print(f"  Checked {len(deps)} packages. Run 'cygnus verify' for full confidence grades.")


def _check_tos():
    """Check if ToS has been accepted. Prompt on first run."""
    cfg = _load_config()
    if cfg.get("tos_accepted"):
        return True
    print("  ──────────────────────────────────────────")
    print("  Cygnus Terms of Service")
    print("  https://blackswan-software.ai/terms")
    print("  ──────────────────────────────────────────")
    print("  By using Cygnus, you agree to the Terms of Service.")
    response = input("  Accept? [y/N] ").strip().lower()
    if response in ("y", "yes"):
        cfg["tos_accepted"] = True
        cfg["tos_accepted_at"] = __import__("datetime").datetime.now().isoformat()
        _save_config(cfg)
        return True
    print("  Terms not accepted. Exiting.")
    sys.exit(0)


def cmd_verify(args):
    """Verify library or project deps. Single lib or auto-detect lockfile.

    Usage:
      cygnus verify requests           # single library
      cygnus verify requests==2.31.0   # specific version
      cygnus verify                    # auto-detect lockfile, verify all deps
      cygnus verify --ci               # CI mode: exit 1 only on SECURITY_ISSUE
    """
    _check_tos()
    library = getattr(args, "library", None)
    # Ecosystem priority: explicit flag > config file > auto-detect > python
    ecosystem = args.ecosystem or _load_config().get("ecosystem") or _detect_ecosystem() or "python"
    ci_mode = getattr(args, "ci", False)
    show_cve = getattr(args, "cve", False)

    # Version pinning: "requests==2.31.0" → library="requests", pin_version="2.31.0"
    pin_version = None
    if library and "==" in library:
        library, pin_version = library.split("==", 1)

    from_lock = getattr(args, "from_lock", False)

    check_sig = getattr(args, "check_signature", False)

    if library:
        # Single library verify
        result = _verify_single(ecosystem, library, pin_version=pin_version,
                                show_cve=show_cve, check_signature=check_sig)
        if ci_mode and result.get("confidence") == "SECURITY_ISSUE_DETECTED":
            sys.exit(1)
    else:
        # Project-wide verify — from cygnus.lock or native lockfile
        if from_lock:
            deps = _parse_cygnus_lock()
            if not deps:
                print("  No cygnus.lock found. Run 'cygnus lock' first.")
                return
            _verify_project(ecosystem, deps, ci_mode)
        else:
            # Multi-ecosystem: if no explicit --ecosystem, detect all and verify each
            if not args.ecosystem:
                ecosystems = _detect_all_ecosystems()
                if not ecosystems:
                    print("  No lockfile found. Specify a library: cygnus verify <library>")
                    return
                total_deps = 0
                any_security_issue = False
                for eco in ecosystems:
                    deps = _parse_lockfile(eco)
                    if deps:
                        if len(ecosystems) > 1:
                            print(f"\n  ── {eco.upper()} ({len(deps)} libraries) ──")
                        total_deps += len(deps)
                        _verify_project(eco, deps, ci_mode)
                if total_deps == 0:
                    print("  No lockfile found. Specify a library: cygnus verify <library>")
            else:
                deps = _parse_lockfile(ecosystem)
                if not deps:
                    print("  No lockfile found. Specify a library: cygnus verify <library>")
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

    # Get per-target manifest (has signature + real filename)
    manifest = _api(f"/artifact/{ecosystem}/{lib_encoded}/{version}/universal/manifest.json?proxy=true")
    if not manifest:
        manifest = _api(f"/manifest/{ecosystem}/{lib_encoded}/{version}")
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

    # Download artifact for verification
    filename = manifest.get("filename", "")
    if not filename or filename == "manifest.json":
        # Try nested artifacts
        for target, info in manifest.get("artifacts", {}).items():
            fn = info.get("filename", "")
            if fn and fn != "manifest.json":
                filename = fn
                break

    if not filename or filename == "manifest.json":
        return {"verified": False, "error": "No artifact filename in manifest"}

    # Download artifact bytes
    cdn_url = f"https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/artifacts/{ecosystem}/{lib_encoded}/{version}/universal/{filename}"
    try:
        req = urllib.request.Request(cdn_url, headers={"User-Agent": "cygnus-cli/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            artifact_data = resp.read()
    except Exception as e:
        return {"verified": False, "error": f"Cannot download artifact: {e}"}

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
        print(f"  Queuing for compilation...")
        _queue_compilation(ecosystem, library)
        print(f"  Run 'cygnus verify {library}' again in ~5 minutes.")
        return {"confidence": "NOT_COMPILED"}

    version = data["version"]
    confidence = data.get("confidence", "ATTESTATION_ONLY")
    token_count = data.get("tokens", 0)
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
    print(f"  Tokens:      {token_count} verified function signatures" if token_count else "  Tokens:      not extracted yet")
    if functions:
        print(f"  Functions:   {', '.join(functions[:5])}")
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
        print(f"  CVEs:        {len(advisories)} known advisory{'s' if len(advisories) != 1 else ''}")
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
    print()

    return {
        "confidence": confidence, "version": version, "tokens": token_count,
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
                for key in pkgs:
                    if key.startswith("node_modules/") and key.count("/") == 1:
                        lib = key.replace("node_modules/", "")
                        if lib and not lib.startswith("."):
                            deps.append(lib)
                if not deps:
                    # v1 format: dependencies at top level
                    deps.extend(data.get("dependencies", {}).keys())
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
                            if lib and lib not in deps:
                                deps.append(lib)
                return deps
            except Exception:
                pass
        # Fallback: yarn.lock
        yarn = cwd / "yarn.lock"
        if yarn.exists():
            try:
                for line in yarn.read_text().splitlines():
                    if line and not line.startswith(" ") and not line.startswith("#"):
                        lib = line.split("@")[0].strip('"')
                        if lib and lib not in deps:
                            deps.append(lib)
                return deps
            except Exception:
                pass
        # Fallback: package.json
        pkg = cwd / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text())
                deps.extend(data.get("dependencies", {}).keys())
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
            _print_verify_summary(prev_results, ci_mode)
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

    # Try batch lookup first (one API call for all deps)
    batch_data = _api_ext_post("/tokens/batch", {
        "ecosystem": ecosystem,
        "libraries": changed_deps,
    })
    if batch_data and batch_data.get("results"):
        batch_results = batch_data["results"]
        for lib in changed_deps:
            br = batch_results.get(lib, {})
            if br.get("status") == "found":
                results[lib] = {
                    "confidence": "VERIFIED",  # Has tokens = at least compiled
                    "version": br.get("version", "?"),
                    "tokens": br.get("token_count", 0),
                }
            else:
                results[lib] = {"confidence": "NOT_COMPILED", "version": None}
                _queue_compilation(ecosystem, lib)
    else:
        # Fallback: individual lookups
        for i, lib in enumerate(changed_deps):
            lib_encoded = lib.replace("/", "__").replace(":", "__")
            # Use pinned version from lockfile if available, otherwise latest
            pinned = _LOCKFILE_VERSIONS.get(lib)
            if pinned:
                ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/{pinned}")
                if not ver_data:
                    ver_data = _api(f"/versions/{ecosystem}/{lib_encoded}/latest")
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
                print(f"    ... {i + 1}/{len(changed_deps)}")

    # Save state for incremental
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({
        "dep_hash": dep_hash,
        "results": results,
        "verified_at": time.time(),
        "ecosystem": ecosystem,
    }, indent=2) + "\n")

    _print_verify_summary(results, ci_mode)


def _print_verify_summary(results: dict, ci_mode: bool):
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
        print(f"\n  No fully verified libraries yet — verification in progress")

    if nc > 0:
        print(f"  {nc} deps not in corpus — queued for compilation")

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
    """Create an account — free or verified (pay-as-you-go).

    Usage:
      cygnus auth signup                      # free tier (any email)
      cygnus auth signup --tier verified      # pay-as-you-go (see pricing page)
      cygnus auth signup --tier enterprise    # enterprise (corporate email required)
    """
    tier_choice = getattr(args, "tier", "free") or "free"

    email = input("  Email: ").strip()
    if not email or "@" not in email:
        print("  Error: valid email required.", file=sys.stderr)
        sys.exit(1)

    if tier_choice == "enterprise":
        domain = email.split("@")[-1].lower()
        personal = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "aol.com",
                     "icloud.com", "protonmail.com", "proton.me", "live.com", "me.com"}
        if domain in personal:
            print(f"  Enterprise trial requires a corporate email address.")
            print(f"  Contact support@blackswan-software.ai for assistance.")
            sys.exit(1)

    # Invite code (required during controlled launch)
    invite_code = input("  Invite code (leave blank if open signup): ").strip()

    # Call signup endpoint
    body = {"email": email, "tier": tier_choice}
    if invite_code:
        body["invite_code"] = invite_code
    payload = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/auth/signup",
        data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 409:
            print(f"  Already registered. Run: cygnus auth login")
            return
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

    api_key = data.get("api_key", "")
    tier = data.get("tier_name", data.get("tier", "free"))

    if not api_key:
        print("  Error: no key returned.", file=sys.stderr)
        sys.exit(1)

    # Auto-save the key (no need for separate login step)
    config = _load_config()
    config["api_key"] = api_key
    config["tier"] = tier
    config["email"] = email
    (CYGNUS_HOME / "config.json").write_text(json.dumps(config, indent=2) + "\n")

    trial_note = data.get("note", "")
    trial_expires = data.get("trial_expires_at", "")

    is_founding = data.get("founding_member", False)

    print(f"\n  Account created!")
    if is_founding:
        spots = data.get("founding_spots_remaining", "?")
        print(f"  ★ FOUNDING MEMBER — Pro tier for 12 months!")
        print(f"  ★ {spots} founding spots remaining")
    print(f"  Email: {email}")
    print(f"  Tier:  {tier.upper()}")
    if trial_expires:
        print(f"  Expires: {trial_expires[:10]}")
    if trial_note and not is_founding:
        print(f"  Note:  {trial_note}")
    print(f"  Key:   {api_key}")
    print(f"\n  Saved to {CYGNUS_HOME / 'config.json'}")
    print(f"\n  Start using:")
    print(f"    cygnus verify")
    print(f"    cygnus install flask")


def cmd_auth_login(args):
    """Prompt for an API key, validate it, and store it in ~/.cygnus/config.json."""
    print("Enter your Cygnus API key (starts with cyg_):")
    try:
        key = getpass.getpass("  Key: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.", file=sys.stderr)
        sys.exit(1)

    if not key:
        print("  Error: no key entered.", file=sys.stderr)
        sys.exit(1)

    # Validate against the auth service
    req = urllib.request.Request(f"{REGISTRY_URL}/auth/validate")
    req.add_header("X-Api-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  Error: invalid API key.", file=sys.stderr)
        else:
            print(f"  Error: {e.code} {e.reason}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"  Connection error: {e}", file=sys.stderr)
        sys.exit(1)

    cfg = _load_config()
    cfg["api_key"] = key
    cfg["tier"] = data.get("tier", "unknown")
    _save_config(cfg)

    tier_name = data.get("tier_name") or data.get("tier", "unknown").upper()
    fingerprint = hashlib.sha256(key.encode()).hexdigest()[:8]
    print(f"  Authenticated. Tier: {tier_name}  Key: ...{fingerprint}")
    print(f"  Credentials stored in {CONFIG_FILE}")


def cmd_auth_status(args):
    """Show current authentication state."""
    env_key = os.environ.get("CYGNUS_API_KEY", "")
    cfg = _load_config()
    cfg_key = cfg.get("api_key", "")

    if env_key:
        key = env_key
        source = "CYGNUS_API_KEY env var"
    elif cfg_key:
        key = cfg_key
        source = str(CONFIG_FILE)
    else:
        print("  Not authenticated.")
        print(f"  Run: cygnus auth login")
        return

    fingerprint = hashlib.sha256(key.encode()).hexdigest()[:8]
    print(f"  Authenticated [{source}]")
    print(f"  Key fingerprint: ...{fingerprint}")
    print(f"  Registry: {REGISTRY_URL}")

    # Fetch usage from server
    usage = _api("/auth/usage", use_cache=False)
    if usage:
        print(f"  Tier: {usage.get('tier', '?').upper()}")
        daily = usage.get("daily_used", 0)
        limit = usage.get("daily_limit", "?")
        remaining = usage.get("daily_remaining", "?")
        print(f"  Today: {daily} requests (limit: {limit}, remaining: {remaining})")
        monthly = usage.get("monthly_used", 0)
        print(f"  This month: {monthly} requests")
    else:
        tier = cfg.get("tier", "unknown") if not env_key else "unknown"
        if tier != "unknown":
            print(f"  Tier: {tier.upper()}")
        print(f"  (server unreachable — usage stats unavailable)")


def cmd_auth_logout(args):
    """Clear stored credentials from ~/.cygnus/config.json."""
    cfg = _load_config()
    if "api_key" not in cfg:
        print("  Not logged in (no key in config).")
        if os.environ.get("CYGNUS_API_KEY"):
            print("  Note: CYGNUS_API_KEY env var is still set — unset it to fully deauthenticate.")
        return
    del cfg["api_key"]
    cfg.pop("tier", None)
    _save_config(cfg)
    print(f"  Logged out. Key cleared from {CONFIG_FILE}")


def cmd_auth_cancel(args):
    """Cancel subscription without uninstalling CLI."""
    cfg = _load_config()
    if not cfg.get("api_key") and not API_KEY:
        print("  Not authenticated. Nothing to cancel.")
        return

    confirm = input("  Cancel your subscription? This does NOT delete your account. [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    url = f"{REGISTRY_URL}/auth/billing/cancel"
    req = urllib.request.Request(url, method="POST")
    req.add_header("User-Agent", "cygnus-cli/1.0")
    req.add_header("X-API-Key", API_KEY or cfg.get("api_key", ""))
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            print(f"  Subscription cancelled. {data.get('message', 'Your account remains active on the free tier.')}")
            cfg["tier"] = "free"
            _save_config(cfg)
    except urllib.error.HTTPError as e:
        body = e.read().decode() if hasattr(e, "read") else ""
        print(f"  Error: {e.code} — {body}", file=sys.stderr)
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)


def cmd_uninstall(args):
    """Uninstall Cygnus CLI — cancel subscription, remove all local data."""
    print("  This will:")
    print(f"    1. Cancel any active subscription")
    print(f"    2. Remove {CYGNUS_HOME}")
    print(f"    3. Remove the cygnus binary")
    confirm = input("  Continue? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    # Cancel subscription (best-effort)
    cfg = _load_config()
    key = API_KEY or cfg.get("api_key", "")
    if key:
        try:
            url = f"{REGISTRY_URL}/auth/billing/cancel"
            req = urllib.request.Request(url, method="POST")
            req.add_header("User-Agent", "cygnus-cli/1.0")
            req.add_header("X-API-Key", key)
            urllib.request.urlopen(req, timeout=15)
            print("  ✓ Subscription cancelled")
        except Exception:
            print("  ⚠ Could not reach server to cancel subscription — cancel manually at auth.blackswan-software.ai")

    # Remove ~/.cygnus/
    import shutil
    if CYGNUS_HOME.exists():
        shutil.rmtree(CYGNUS_HOME, ignore_errors=True)
        print(f"  ✓ Removed {CYGNUS_HOME}")

    # Remove binary
    binary = Path(sys.argv[0]).resolve()
    try:
        binary.unlink()
        print(f"  ✓ Removed {binary}")
    except Exception:
        print(f"  ⚠ Could not remove {binary} — delete manually")

    print("  Cygnus uninstalled. Thanks for trying it.")


def cmd_auth_cancel(args):
    """Cancel subscription without uninstalling. Account stays active on free tier."""
    cfg = _load_config()
    key = API_KEY or cfg.get("api_key", "")
    if not key:
        print("  Not authenticated. Run: cygnus auth login")
        return

    print("  This will cancel your paid subscription.")
    print("  Your account stays active on the free tier (the daily quota).")
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
        print(f"\n  Your API key still works for free tier (the daily quota).")
        print(f"  To reactivate: visit https://blackswan-software.ai/pricing")
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
        print("  Not authenticated. Run: cygnus auth login")
        sys.exit(1)

    # --stripe-test sets env to override server flag (server still authoritative)
    headers = {"X-API-Key": api_key}
    if args.stripe_test:
        headers["X-Stripe-Test-Mode"] = "1"

    try:
        import urllib.request, urllib.error, json as _json
        req = urllib.request.Request(
            f"{REGISTRY_URL.replace(':8001', ':8007')}/auth/billing/balance"
            if ":8001" in REGISTRY_URL
            else f"{REGISTRY_URL}/auth/billing/balance",
            headers=headers,
        )
        # Easier: hit auth.blackswan-software.ai directly
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
    print(f"  Stripe enabled:   {'YES (live)' if stripe_on else 'NO (test/stub mode)'}")
    if not stripe_on:
        print(f"  Note: STRIPE_ENABLED is off — checkout endpoints return stub URLs.")
    if charges:
        print(f"\n  Recent charges ({len(charges)}):")
        for c in charges[-10:][::-1]:
            delta = c.get("delta_cents", 0)
            sign = "+" if delta > 0 else ""
            reason = c.get("reason", "?")
            ts = c.get("ts", "")[:19]
            print(f"    {ts}  {sign}${delta / 100:>7.2f}  {reason}")
    if balance_usd == 0:
        print(f"\n  Deposit: visit https://blackswan-software.ai/pricing")
        print(f"  Or run:  cygnus account --json (to script via API)")


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
    else:
        print("Usage: cygnus auth <signup|login|status|logout|cancel>")
        print("  signup  — create account (free or Verified-tier deposit pay-as-you-go)")
        print("  login   — authenticate with existing API key")
        print("  status  — show current auth state + balance")
        print("  logout  — clear stored credentials")
        print("  cancel  — cancel subscription (keep account)")


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
        print("  Usage: cygnus cache [clear|status]")


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
                print(f"    Run: cygnus auth signup")
                print()
        except Exception:
            pass

        print("  Get started:")
        print("    cygnus verify               Scan this project's dependencies")
        print("    cygnus verify <library>      Check a specific library")
        print("    cygnus check                 Scan for known CVEs")
        print("    cygnus auth signup           Create account (free, the daily quota)")
        print()
        print("  Free: grade + CVE for the daily quota. No payment required.")
        print("  See pricing page for full tokens + artifacts (pay-as-you-go, no subscription).")

    else:
        # Returning user
        if lockfile_deps:
            print(f"  {len(lockfile_deps)} {ecosystem} dependencies detected.")
            print()
            print("    cygnus verify               Verify all deps (incremental, cached 24h)")
            print("    cygnus check                Scan for known CVEs")
            print("    cygnus verify --ci          CI mode (JSON output, exit 1 on security issues)")
        else:
            print("  Commands:")
            print("    cygnus verify <library>      Check a specific library")
            print("    cygnus check                 Scan for known CVEs")
            print("    cygnus install <library>     Download signed artifact")
            print("    cygnus auth status           Account + usage stats")
    print()


def _parse_cygnus_lock() -> list[str]:
    """Parse cygnus.lock to get library names."""
    lock_file = Path.cwd() / "cygnus.lock"
    if not lock_file.exists():
        return []
    deps = []
    for line in lock_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: library==version  confidence=X  tokens=N  signed=yes  grade=A
        lib = line.split("==")[0].strip()
        if lib:
            deps.append(lib)
    return deps


# NOTE: _detect_ecosystem() is defined at line 216 with full 15-ecosystem support.
# A duplicate was here that only detected 7 ecosystems — removed. See test_cli.py.


# ── `cygnus issue` ─────────────────────────────────────────────────────
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
    """Try /auth/usage first (authenticated), fall back to git config."""
    data = _api("/auth/usage", use_cache=False)
    if isinstance(data, dict) and data.get("email"):
        return data["email"]
    try:
        r = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True, text=True, timeout=2,
        )
        return r.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def cmd_issue(args):
    """File a bug or feature request — `cygnus issue [title]`.

    Slogan: <name>, file an issue. We're building trust.

    Strategy:
      1. Try `gh issue create` (if user has gh CLI) — best UX
      2. Fallback: print a github.com URL with the body pre-filled
    """
    import platform
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


def main():
    parser = argparse.ArgumentParser(
        prog="cygnus",
        description="Pre-compiled artifacts alongside your package manager.",
    )
    parser.add_argument("--ecosystem", "-e", default=None,
                        help="Ecosystem (default: auto-detect, or python)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass local cache (always hit API)")

    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Set up ~/.cygnus/ and configure resolution")
    p_init.add_argument("--ecosystem", "-e", default=None,
                        help="Ecosystem (overrides auto-detect)")
    p_init.add_argument("--global", dest="use_global", action="store_true",
                        help="Install hook at user level (e.g. ~/.nuget/, ~/.cargo/) instead of project")

    p_install = sub.add_parser("install", help="Install compiled artifact")
    p_install.add_argument("library", nargs="?", default=None, help="Library name (or use --from-lock)")
    p_install.add_argument("version", nargs="?", default="latest", help="Version (default: latest)")
    p_install.add_argument("--from-lock", action="store_true", help="Install all deps from cygnus.lock")
    p_install.add_argument("--ci", action="store_true", help="CI mode: fall back to native package manager if artifact unavailable, never prompt, exit 0")

    sub.add_parser("list", help="Show installed Cygnus artifacts")
    p_check = sub.add_parser("check", help="Check for updates and CVEs")
    p_check.add_argument("library", nargs="?", default=None, help="Library name (or scan all from lockfile)")
    p_check.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")

    p_lock = sub.add_parser("lock", help="Generate cygnus.lock (verification manifest)")
    p_lock.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")

    p_sbom = sub.add_parser("sbom", help="Generate CycloneDX SBOM")
    p_sbom.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_sbom.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")

    p_verify = sub.add_parser("verify", help="Verify a library or all project deps")
    p_verify.add_argument("library", nargs="?", default=None, help="Library name or lib==version for pinning")
    p_verify.add_argument("--ecosystem", "-e", default=None, help="Ecosystem (default: auto-detect)")
    p_verify.add_argument("--ci", action="store_true", help="CI mode: JSON output, exit 1 only on security issues")
    p_verify.add_argument("--check-signature", action="store_true", help="Verify Ed25519 signature against published keys")
    p_verify.add_argument("--cve", action="store_true", help="Show known CVEs/security advisories for this version")
    p_verify.add_argument("--from-lock", action="store_true", help="Verify from cygnus.lock (no native lockfile needed)")

    p_auth = sub.add_parser("auth", help="Manage authentication")
    auth_sub = p_auth.add_subparsers(dest="auth_command")
    p_signup = auth_sub.add_parser("signup", help="Create account (free or pay-as-you-go)")
    p_signup.add_argument("--tier", choices=["free", "verified", "enterprise"], default="free",
                          help="Account tier (verified=Verified-tier deposit pay-as-you-go, enterprise=contact us)")
    auth_sub.add_parser("login", help="Authenticate with your Cygnus API key")
    auth_sub.add_parser("status", help="Show current auth state and key fingerprint")
    auth_sub.add_parser("logout", help="Clear stored credentials")
    auth_sub.add_parser("cancel", help="Cancel subscription (keep account on free tier)")

    sub.add_parser("uninstall", help="Uninstall Cygnus — cancel subscription + remove all data")

    p_cache = sub.add_parser("cache", help="Manage local cache")
    cache_sub = p_cache.add_subparsers(dest="cache_command")
    cache_sub.add_parser("clear", help="Clear all cached results")
    cache_sub.add_parser("status", help="Show cache stats")

    p_account = sub.add_parser("account", help="Show balance + usage (verified tier)")
    p_account.add_argument("--stripe-test", action="store_true",
                           help="Test mode: shows balance from stub endpoints (no real charges)")
    p_account.add_argument("--json", action="store_true", help="JSON output")

    p_issue = sub.add_parser(
        "issue",
        help="File a bug report or feature request — we read every one",
    )
    p_issue.add_argument("title", nargs="?", default=None,
                         help="One-line title (prompts if missing)")
    p_issue.add_argument("--body", default=None,
                         help="Issue body (opens $EDITOR if not provided)")

    args = parser.parse_args()

    # argparse subparsers override parent --ecosystem with None.
    # If user put --ecosystem before the subcommand, extract it from sys.argv.
    if not args.ecosystem:
        for i, arg in enumerate(sys.argv):
            if arg in ("--ecosystem", "-e") and i + 1 < len(sys.argv):
                args.ecosystem = sys.argv[i + 1]
                break

    # Validate ecosystem against allowlist before any URL construction.
    # Prevents URL injection / messy error paths when user passes garbage.
    args.ecosystem = _validate_ecosystem(args.ecosystem)

    # Apply --no-cache globally
    if getattr(args, "no_cache", False):
        global CACHE_TTL
        CACHE_TTL = 0

    if args.command == "init":
        cmd_init(args)
    elif args.command == "install":
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
    elif args.command == "auth":
        cmd_auth(args)
    elif args.command == "cache":
        cmd_cache(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    elif args.command == "account":
        cmd_account(args)
    elif args.command == "issue":
        cmd_issue(args)
    else:
        # First-run experience: no command → onboarding
        _first_run_onboarding()


if __name__ == "__main__":
    main()
