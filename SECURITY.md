# Security Policy

## Project maturity

This repository is an early batch-processing foundation and is not
production-ready. It does not include a model, dataset, service endpoint, or
deployment configuration. It includes an optional authenticated local CLI
workspace, which is not a remotely exposed identity or authorization service.

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
isolate the predictor, remove sensitive fields, detect malicious content, or
provide a network service.

The optional local workspace adds password authentication, service-layer role
checks, session expiry, retention, and audit boundaries for its own operations.
It does not protect against the operating-system account that owns the database,
host administrators, copied database files, or code in the same process. It
does not provide TLS, SSO, HTTP cookies, CSRF protection, or brute-force rate
limits because it opens no network listener. Integrators remain responsible for
least privilege, data minimization, explicit resource limits, storage
encryption, backups, and deployment security.

## Supported versions

No stable supported release exists yet. Security fixes apply to the latest
development commit until a versioning policy is adopted.
