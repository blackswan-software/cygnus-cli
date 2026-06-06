# cygnus-cli tests

This directory holds **CLI development tests** — pytest files that
exercise argparse plumbing, command handlers, and regression cases
against the CLI source.

```
tests/
  test_cli_regressions_2026_06_05.py  ← pinned fixes for fresh-user bugs
```

Run with:

```
python -m pytest tests/ -q
```

## What does NOT live here

**User-UX scenario tests** — the kind where a fresh Claude session
role-plays a new user installing the CLI and trying it on a real
project — live in an isolated, dev-disconnected repo:

- `blackswan-user/tests/<NNN>-<name>/PROMPT.md`

Those scenarios import nothing from this repo and are operated by a
separate pilot session against the published CLI binary on
`install.blackswan-software.ai`. They are deliberately walled off from
this codebase so the pilot can't "cheat" by reading our internals.

If you're touching CLI UX (command names, prompts, error wording),
update the matching PROMPT.md in `blackswan-user` so the user-scenario
test still describes what users actually see.
