# Local authenticated workspace

## Status and scope

The workspace is an alpha, local-first reference implementation. It turns the
fail-closed classifier into a consult-and-export workflow with separate users,
roles, retention periods, and privacy-minimal audit events. The workspace CLI
does not start a network listener and is not a production identity service. A
separate optional [web adapter](web-workspace.md) can expose the same service on
loopback only.

The first slice deliberately supports one organization per database. It uses
SQLite from the Python standard library so the authorization and retention
boundaries can be exercised offline. Any future remotely accessible service
will still need a separate threat model, rate limiting, TLS, migrations,
backup/restore procedures, and a server database.

## Role matrix

| Action | Admin | Analyst | Viewer |
| --- | --- | --- | --- |
| View and export classification results | yes | yes | yes |
| Create and complete classification jobs | yes | yes | no |
| Request retention of original source bytes | yes | no | no |
| Access an optionally retained raw payload | yes | no | no |
| Create users | yes | no | no |
| Change or execute retention policy | yes | no | no |
| Read the audit trail | yes | no | no |

Authorization is checked in the workspace service for every operation. The
database stores only a SHA-256 digest of each session token. Passwords use
individually salted `scrypt` hashes. Sessions expire after eight hours by
default and can never exceed 24 hours.

## Retention model

The defaults are:

| Data class | Default |
| --- | ---: |
| Original source bytes, when explicitly retained | 30 days |
| Classification results | 90 days |
| Privacy-minimal audit events | 180 days |

Raw source storage is off by default. A policy change affects newly created
jobs; it does not silently rewrite existing expiry timestamps. At the exact
expiry boundary the application stops returning the data, even before a purge
runs. Purge clears expired raw payloads, removes expired jobs and sessions, and
removes audit events beyond their separate threshold.

SQLite `secure_delete` is enabled and the database file is set to mode `0600`.
This is not encryption at rest and does not prove erasure from SSDs,
copy-on-write filesystems, snapshots, or backups. Deployers remain responsible
for filesystem permissions, encryption, backups, and a legally justified
retention policy.

## Offline quick start

Install the package in a Python 3.12+ virtual environment, then initialize a
private workspace. Passwords are requested interactively and are not accepted
as command-line arguments.

```console
log-classify workspace init ./state/workspace.sqlite3 sample-org owner
log-classify workspace user-add ./state/workspace.sqlite3 sample-org owner \
  reviewer --role viewer
```

Classify synthetic JSONL. Only complete, validated results become visible in
the database. The source bytes are not retained by default.

```console
log-classify workspace classify ./state/workspace.sqlite3 sample-org owner \
  ./examples/input-valid.jsonl
log-classify workspace jobs ./state/workspace.sqlite3 sample-org owner
log-classify workspace show ./state/workspace.sqlite3 sample-org owner <job-id>
```

Explicit raw retention is available for controlled local testing:

```console
log-classify workspace classify ./state/workspace.sqlite3 sample-org owner \
  ./examples/input-valid.jsonl --store-raw
```

Set and inspect a policy, then run the idempotent purge operation:

```console
log-classify workspace retention-set ./state/workspace.sqlite3 sample-org owner \
  --raw-days 7 --result-days 30 --audit-days 180
log-classify workspace retention-show ./state/workspace.sqlite3 sample-org owner
log-classify workspace purge ./state/workspace.sqlite3 sample-org owner
log-classify workspace audit ./state/workspace.sqlite3 sample-org owner
```

## Security boundaries

- The workspace stores no default credentials and never accepts passwords as
  CLI parameters.
- Raw messages are excluded from predictions and audit details.
- Viewer and analyst roles cannot request stored raw source bytes.
- Job identifiers are random UUIDs and every job query is organization-scoped.
- Synchronous CLI classification finishes in a temporary directory before the
  successful job and its audit event are committed in one database transaction;
  a model or validation failure in that path leaves no visible job.
- The optional web path intentionally persists privacy-minimal queued and
  terminal failure states for progress and diagnosis, while still publishing
  result records only after complete success.
- Schema v1 workspaces are migrated transactionally to v2 on explicit
  initialization or web startup. Unknown schemas and missing web database paths
  fail before creation or DDL.
- The database rejects a symlink path and is restricted to the process owner.

The current implementation does not protect data from the operating-system
account that owns the database, host administrators, copied database files, or
malicious code running in the same process. Its audit trail is transactional,
but it is not tamper-proof or externally anchored.
