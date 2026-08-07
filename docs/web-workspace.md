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

The default queue admits at most eight jobs, including the one running job,
and reports progress every 16 records. Both values are explicit CLI controls:

```console
.venv/bin/log-classify web ./state/workspace.sqlite3 \
  --queue-capacity 8 --worker-batch-size 16
```

The rules baseline is available without model dependencies. To expose the
known profiles in the selector, install both extras and enable them. Predictors
remain lazy and downloads remain disabled by default:

```console
.venv/bin/python -m pip install '.[web,ml]'
.venv/bin/log-classify web ./state/workspace.sqlite3 \
  --enable-model-profile english-deberta-v1 \
  --enable-model-profile multilingual-minilm-v1 \
  --enable-model-profile multilingual-mdeberta-v1 \
  --enable-model-profile multilingual-bge-m3-v1
```

Local model identity and revision must match the selected registered profile,
but directory contents are not verified until artifact-manifest verification
is implemented. Model weights, caches, tokenizers, logs, and datasets must
remain outside this repository.

## Roles and data exposure

| Operation | Admin | Analyst | Viewer |
| --- | --- | --- | --- |
| Consult and export stored results | yes | yes | yes |
| Upload and classify JSONL | yes | yes | no |
| Cancel own active job | yes | yes | no |
| Cancel another user's active job | yes | no | no |
| Create users and change retention | yes | no | no |
| Read the audit trail | yes | no | no |

The web surface never requests durable raw-source retention and never exports
source messages. After complete validation, bounded source bytes wait only in
the process-local in-memory queue. The worker uses a private `0600` temporary
file and removes it after execution. Raw bytes and bearer tokens are never
stored in SQLite; a job stores only the source digest, counts, model name,
state, timestamps, sanitized failure code, and an internal capability hash.
RAM is not an erasure boundary: the source can still be visible to the owning
OS account, swap, a core dump, or malicious code in the process.

## HTTP API

The interactive documentation is available locally at `/api/v1/docs`. API
clients create a short-lived session with `POST /api/v1/sessions` and send the
returned opaque value as `Authorization: Bearer <token>`. Tokens are displayed
only in the session-creation response; the database stores their SHA-256
digests. `DELETE /api/v1/session` revokes the current session.

The API accepts either JSON records at `/api/v1/classifications` or a multipart
JSONL file at `/api/v1/classifications/file`. Both validate the complete input,
admit it to the bounded queue, and return `202 Accepted` with `Location`,
`Retry-After: 1`, a job ID, and a status URL. Result exports use NDJSON and are
available only after terminal success.

| Method and path | Purpose |
| --- | --- |
| `POST /api/v1/sessions` | Create an eight-hour opaque session |
| `DELETE /api/v1/session` | Revoke the current bearer session |
| `GET /api/v1/me` | Inspect the current principal |
| `POST /api/v1/classifications` | Validate and queue a bounded JSON `records` array |
| `POST /api/v1/classifications/file` | Validate and queue a bounded multipart JSONL upload |
| `GET /api/v1/jobs?limit=50&offset=0` | List recent jobs with `next_offset` |
| `GET /api/v1/jobs/{id}` | Read one organization-scoped job |
| `GET /api/v1/jobs/{id}/status` | Poll progress without adding audit events |
| `POST /api/v1/jobs/{id}/cancel` | Cancel queued work or request a chunk-boundary cancellation |
| `GET /api/v1/jobs/{id}/export` | Export available results as NDJSON |
| `/api/v1/admin/*` | Admin-only users, retention, purge, and audit operations |

Expired or purged jobs are not visible and return the same `404` as an unknown
or cross-organization identifier. A known job without completed results cannot
be exported and returns `409`; it is never represented as a successful empty
file. List `limit` is 1–200 and `offset` is 0–100000.

Job states are `queued`, `running`, `cancelling`, `succeeded`, `failed`, and
`cancelled`. “Processed” means predictor outputs validated and staged so far;
it never means partial results are published. Cancellation is cooperative:
Python cannot safely terminate a model call in another thread, so a running
request remains `cancelling` until the current predictor chunk returns. If
completion and cancellation race, a state-version compare-and-swap permits
only one terminal transition.

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
- Every state-changing UI request requires an exact same-origin check before
  form or upload parsing. Login and unauthenticated locale selection use a
  pre-session double-submit CSRF token; authenticated operations use a
  session-bound token.
- API and UI authorization occurs before classification request bodies are
  parsed or predictors are invoked.
- Request, input-byte, record-count, queue-capacity, and worker-chunk limits fail
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

Only one web worker may own a workspace database. A private POSIX lock file
prevents a second process from recovering or executing its jobs. On startup,
active jobs left by a prior process become `failed` with the stable code
`interrupted`; they are not retried because their raw bytes were deliberately
not persisted. Logging out or allowing the accepting session to expire does
not revoke work that was already authorized and queued.

## Current language scope

The browser interface is available in English, Italian, French, and Spanish. A
protected language selector stores an `HttpOnly`, `SameSite=Strict` cookie;
otherwise the UI negotiates `Accept-Language` and falls back to English.
Translation catalogs are packaged and cross-validated at startup. API fields,
problem codes, taxonomy labels, model IDs, and JSONL exports remain stable
English machine values.

UI language does not select or translate classification input. The rules
baseline is English-oriented. `english-deberta-v1` is the default experimental
profile. The opt-in `multilingual-minilm-v1`,
`multilingual-mdeberta-v1`, and `multilingual-bge-m3-v1` profiles cover the
English, Italian, French, and Spanish software path at increasing resource
cost. Only MiniLM completed the current CPU fixture, and its measured quality
is not sufficient to make it a default. UI locale and model language are
independent choices.
