# Local web security validation — 2026-08-07

## Scope

This report records local verification of the optional authenticated web
workspace. It uses only generated credentials, temporary SQLite databases, and
synthetic log messages. It is implementation evidence for an alpha localhost
workflow, **not** a production security assessment or penetration test.

## Results

| Check | Result |
| --- | --- |
| Complete suite with `web` and `test` extras | 129 tests passed |
| Core-only environment | 106 tests passed; 23 web tests intentionally skipped |
| Python/TOML parsing | passed |
| `git diff --check` | passed |
| Local wheel build | passed |
| Web templates, static assets, and locale catalogs in wheel | 10 of 10 present |
| Private-IP and common credential-pattern scan | no matches |

The web integration cases cover:

- strict Host validation, no CORS opt-in, security headers, and HTTPS-only HSTS;
- bearer-only API authentication, ambiguous cookie/bearer rejection, logout,
  and server-side session revocation;
- pre-session and session-bound CSRF plus exact Origin checks for
  state-changing UI requests;
- viewer denial before upload parsing and predictor invocation;
- byte, record, whole-request, multipart, and streamed-body limits;
- ignored hostile filenames and privacy-minimal result export;
- HTML autoescaping for untrusted model metadata;
- validated English, Italian, French, and Spanish catalogs, bounded language
  negotiation, protected locale cookies, and unchanged API machine codes;
- lazy model-profile registration without artifact loading at web startup;
- bounded asynchronous admission, immediate `202`, persistent job states,
  monotonic chunk progress, cooperative cancellation, and terminal-only result
  publication;
- hashed worker capabilities instead of queued bearer tokens, logout-independent
  accepted work, read-only status polling, restart recovery, and a tested
  single-instance lock;
- hard-link database aliases rejected on every open, late worker shutdown lock
  release, and submit/close serialization without stranded jobs;
- queue saturation without orphan jobs, best-effort queued-byte zeroing on
  cancellation, and missing-database startup without implicit file or directory
  creation;
- admin-only users, retention, purge, and audit surfaces;
- loopback-only CLI binding with proxy headers and access logging disabled;
- OpenAPI containing API routes but not browser UI routes.

## Reproduction

Core-only suite:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
```

Web integration suite in an isolated environment:

```console
python3 -m venv .venv-web-test
.venv-web-test/bin/python -m pip install '.[web,test]'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  .venv-web-test/bin/python -W error -m unittest discover -s tests -v
```

The repository CI has a separate web matrix for Python 3.12 and 3.13 using the
same extras and warning-as-error test command. This report describes local
execution; hosted CI must still run on the future commit before any tag or
release.

## Residual limitations

- The server is supported only on loopback and has no brute-force rate limiter,
  TLS termination, reverse-proxy trust, or remote deployment profile.
- SQLite and the in-process predictor are not isolation boundaries.
- Queue source bytes are transient but can still be exposed through process
  memory, swap, core dumps, or the owning OS account. They are not durable and
  interrupted jobs cannot be resumed.
- Authorization denials are not all represented as audit events.
- A model call cannot be killed safely inside its Python thread; cancellation
  takes effect only after the current predictor chunk returns.
- Request duration and slow-client limits depend on the ASGI server or a future
  explicitly configured ingress boundary.
- Multilingual model quality, load behavior, concurrent purge/view races, and
  client disconnect cleanup need additional measured campaigns. UI
  localization is verified but does not imply classifier accuracy.
- No independent security review has been completed.
