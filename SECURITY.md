# Security Policy

## Project maturity

This repository is an early batch-processing foundation and is not
production-ready. It does not include a model, dataset, remote deployment, or
production configuration. It includes an optional authenticated local CLI and
localhost web workspace, neither of which is a remotely supported identity or
authorization service.

## Reporting a vulnerability

Do not include credentials, private keys, access tokens, real logs, customer
data, or operational identifiers in a report. Use the repository's private
vulnerability-reporting channel when it is enabled. Otherwise, keep the finding
local and coordinate a private reporting method with the maintainer.

Include the affected version or commit, a minimal synthetic reproducer, the
expected behavior, the observed behavior, and the security impact. Avoid public
disclosure until the maintainer has acknowledged the report and agreed on a
timeline.

## Security boundary

The core library validates JSONL structure and the batch/predictor cardinality
contract. It does not authenticate callers, authorize source-file access,
isolate the predictor, remove sensitive fields, or detect malicious content.

The optional local workspace adds password authentication, service-layer role
checks, session expiry, retention, and audit boundaries for its own operations.
The web adapter adds loopback HTTP, strict host validation, bounded requests,
same-origin checks, pre-session double-submit CSRF for login, session-bound
CSRF for authenticated operations, secure response headers, and
`HttpOnly`/`SameSite=Strict` cookies. Authorization is checked before upload
parsing or predictor invocation. Failed logins are bounded by privacy-minimal,
in-process account and direct-source windows. The web surface does not retain
raw uploads.

These controls do not protect against the operating-system account that owns
the database, host administrators, copied database files, or code in the same
process. The login limiter resets on process restart and is not a distributed
or remote-deployment control. The web adapter does not provide TLS termination,
SSO, account recovery, reverse-proxy trust, or a supported remote deployment.
Integrators remain responsible for least privilege, data
minimization, storage encryption, backups, and a legally justified retention
policy. Do not expose the alpha server beyond loopback.

## Supported versions

No stable supported release exists yet. Security fixes apply to the latest
development commit until a versioning policy is adopted.
