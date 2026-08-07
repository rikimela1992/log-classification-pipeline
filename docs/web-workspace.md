# Authenticated local web workspace

## Status and intended use

The optional web extra provides an alpha, localhost-only interface over the
same authenticated workspace used by the CLI. It is intended for one operator
or a small trusted team on one machine to classify sanitized JSONL, consult
completed jobs, and export privacy-minimal results.

It is **not production-ready** and must not be exposed directly to a LAN or the
Internet. It has no TLS termination, reverse-proxy trust configuration,
distributed rate limiting, SSO, account recovery, or server-database support.

## Quick start

Create a virtual environment, install the web extra, and initialize a workspace.
Passwords are prompted interactively and no default credentials exist.

```console
python3 -m venv .venv
.venv/bin/python -m pip install '.[web]'
.venv/bin/log-classify workspace init ./state/workspace.sqlite3 sample-org owner
.venv/bin/log-classify web ./state/workspace.sqlite3
```

Open `http://127.0.0.1:8080/app`. The command binds only to `127.0.0.1`, disables
proxy-header trust and access logging, and refuses an unknown or unsafe
workspace database. Stop it with `Ctrl-C`.

The rules baseline is available without model dependencies. To add the
experimental zero-shot choice, install both extras and identify a local model
directory explicitly:

```console
.venv/bin/python -m pip install '.[web,ml]'
.venv/bin/log-classify web ./state/workspace.sqlite3 \
  --adapter zero-shot \
  --model-source /path/to/local/model \
  --model-id <declared-model-id> \
  --model-revision <declared-revision>
```

Local model identity and revision are caller-declared until artifact-manifest
verification is implemented. Model weights, caches, tokenizers, logs, and
datasets must remain outside this repository.

## Roles and data exposure

| Operation | Admin | Analyst | Viewer |
| --- | --- | --- | --- |
| Consult and export stored results | yes | yes | yes |
| Upload and classify JSONL | yes | yes | no |
| Create users and change retention | yes | no | no |
| Read the audit trail | yes | no | no |

The web surface never requests raw-source retention and never exports source
messages. Uploads are staged in private temporary files, bounded before model
invocation, and removed after the request. Stored results contain labels,
scores, abstention, declared model provenance, counts, and a source digest.

## HTTP API

The interactive documentation is available locally at `/api/v1/docs`. API
clients create a short-lived session with `POST /api/v1/sessions` and send the
returned opaque value as `Authorization: Bearer <token>`. Tokens are displayed
only in the session-creation response; the database stores their SHA-256
digests. `DELETE /api/v1/session` revokes the current session.

The API accepts either JSON records at `/api/v1/classifications` or a multipart
JSONL file at `/api/v1/classifications/file`. Both return `201` with a job ID and
batch summary only after complete classification and storage. Result exports
use NDJSON.

| Method and path | Purpose |
| --- | --- |
| `POST /api/v1/sessions` | Create an eight-hour opaque session |
| `DELETE /api/v1/session` | Revoke the current bearer session |
| `GET /api/v1/me` | Inspect the current principal |
| `POST /api/v1/classifications` | Classify a bounded JSON `records` array |
| `POST /api/v1/classifications/file` | Classify a bounded multipart JSONL upload |
| `GET /api/v1/jobs?limit=50&offset=0` | List recent jobs with `next_offset` |
| `GET /api/v1/jobs/{id}` | Read one organization-scoped job |
| `GET /api/v1/jobs/{id}/export` | Export available results as NDJSON |
| `/api/v1/admin/*` | Admin-only users, retention, purge, and audit operations |

Expired or purged jobs are not visible and return the same `404` as an unknown
or cross-organization identifier. A known job without completed results cannot
be exported and returns `409`; it is never represented as a successful empty
file. List `limit` is 1–200 and `offset` is 0–100000.

After Host validation, application and API errors use
`application/problem+json` with an opaque request ID and stable `code`; details
never include input messages, passwords, tokens, database paths, or model paths.
An untrusted Host is rejected earlier with Starlette's minimal `400` response.
Principal application codes are `401` unauthenticated, `403` unauthorized,
`404` not visible, `409` conflict, `413` limit exceeded, `422` invalid request,
and `503` unavailable workspace or model. Cookie and bearer authentication
cannot be combined, CORS is not enabled, and UI routes are excluded from the
OpenAPI document.

## Security behavior

- Host headers are allow-listed; the CLI configures only localhost names.
- UI sessions use `HttpOnly`, `SameSite=Strict` cookies with no `Domain`.
- Every state-changing UI request requires an exact same-origin check and a
  session-bound CSRF token before form or upload parsing.
- API and UI authorization occurs before classification request bodies are
  parsed or predictors are invoked.
- Request, input-byte, record-count, and per-model concurrency limits fail
  closed. Application errors after Host validation return sanitized problem
  documents without input content.
- HTML templates autoescape model and result fields. Local CSS and JavaScript
  work under a restrictive Content Security Policy.
- With the default local HTTP profile the cookie is not marked `Secure` and
  HSTS is disabled. `cookie_secure=True` exists for an embedding that already
  supplies correctly configured HTTPS, but that deployment is not supported by
  the CLI in this alpha.

There is not yet a brute-force rate limiter. The database audit records login
failures without the submitted username or password, but authorization denials
are not all audit events. Use only synthetic or already-sanitized data and keep
the database on a private, encrypted filesystem where appropriate.

The browser workflow requires its bundled JavaScript to add the CSRF header to
protected forms. A visible `<noscript>` warning explains this dependency; the
bearer API remains available without browser JavaScript.

## Current language scope

The web interface is currently English. The rules baseline and recommended
DeBERTa NLI adapter are also English-oriented. Italian, French, Spanish, and
English UI localization plus an explicitly multilingual model profile are
planned as a separate measured feature; no multilingual accuracy claim is made
yet.
