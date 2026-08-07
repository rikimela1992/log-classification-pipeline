# Local web security validation — 2026-08-07

## Scope

This report records local verification of the optional authenticated web
workspace. It uses only generated credentials, temporary SQLite databases, and
synthetic log messages. It is implementation evidence for an alpha localhost
workflow, **not** a production security assessment or penetration test.

## Results

| Check | Result |
| --- | --- |
| Complete suite with `web` and `test` extras | 108 tests passed |
| Core-only environment | 92 tests passed; 16 web tests intentionally skipped |
| Python/TOML parsing | passed |
| `git diff --check` | passed |
| Local wheel build | passed |
| Web templates and static assets in wheel | 6 of 6 present |
| Private-IP and common credential-pattern scan | no matches |

The web integration cases cover:

- strict Host validation, no CORS opt-in, security headers, and HTTPS-only HSTS;
- bearer-only API authentication, ambiguous cookie/bearer rejection, logout,
  and server-side session revocation;
- session-bound CSRF plus exact Origin checks for state-changing UI requests;
- viewer denial before upload parsing and predictor invocation;
- byte, record, whole-request, multipart, and streamed-body limits;
- ignored hostile filenames and privacy-minimal result export;
- HTML autoescaping for untrusted model metadata;
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
- Authorization denials are not all represented as audit events.
- Request duration and slow-client limits depend on the ASGI server or a future
  explicitly configured ingress boundary.
- Multilingual model quality, load behavior, concurrent purge/view races, and
  client disconnect cleanup need additional measured campaigns.
- No independent security review has been completed.
