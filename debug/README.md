# Debug binaries

**Not for production distribution.** GitHub Releases at
`https://github.com/blackswan-software/cygnus-cli/releases` is the canonical
source — these are local PyInstaller builds for faster operator validation
while a release-build is in flight.

## Contents

| File | Notes |
|---|---|
| `cygnus-linux-x86_64-v0.1.7-local` | PyInstaller `--onefile` from master at b962084. SHA-256 in the `.sha256` file. Built on Ubuntu 24.04 / glibc 2.35; should run on Ubuntu 22.04 LTS + Debian 12. |

## Test it

```sh
chmod +x cygnus-linux-x86_64-v0.1.7-local
./cygnus-linux-x86_64-v0.1.7-local --version           # → cygnus 0.1.7
./cygnus-linux-x86_64-v0.1.7-local verify              # cpp scan works now
./cygnus-linux-x86_64-v0.1.7-local issue --body smoke  # no NameError
./cygnus-linux-x86_64-v0.1.7-local request --help      # new command
```

## Known production issue: forgot-key emails not delivered

`cygnus auth forgot-key` returns the "if registered, reset sent" success
message, but **no email actually arrives**. This is **not a CLI bug** —
the CLI does its job. Auth-service logs on M1 show:

```
Resend failed for <email>: HTTP Error 403: Forbidden — trying SMTP fallback
No email transport configured — email to <email> not sent
```

Root cause = both email transports are broken on the auth-service:

| Var | State | Effect |
|---|---|---|
| `RESEND_API_KEY` | set, but Resend returns 403 | API key invalid / domain unverified |
| `SMTP_HOST` | `smtp.purelymail.com` | set |
| `SMTP_USER` | set | OK |
| `SMTP_PASSWORD` | **missing** | SMTP fallback fails silently |
| `MAIL_FROM` | **missing** | no `from` address |

Operator fix (one of):

- Renew the Resend API key (and confirm sending domain is verified at
  resend.com), then `docker compose -f docker-compose.control.yml up -d
  --no-build auth-service` on M1, OR
- Add `SMTP_PASSWORD` + `MAIL_FROM` to `/opt/blackswan/cygnus/.env` on M1
  and re-up the auth-service container.

The CLI v0.1.7 already handles a 403 from the endpoint with a clear
support@blackswan-software.ai recovery path, but in the current state
the endpoint returns **200** (lying about success). Until the email
transport is fixed, users hitting forgot-key will need the manual
support@ path even though the CLI doesn't surface it.
