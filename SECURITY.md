# Security Policy

## Project maturity

This repository is an early batch-processing foundation and is not
production-ready. It does not include a model, dataset, service endpoint, or
deployment configuration.

## Reporting a vulnerability

Do not include credentials, private keys, access tokens, real logs, customer
data, or operational identifiers in a report. Once a remote repository exists,
use its private vulnerability-reporting channel if enabled. Until then, keep the
finding local and coordinate a private reporting method with the maintainer.

Include the affected version or commit, a minimal synthetic reproducer, the
expected behavior, the observed behavior, and the security impact. Avoid public
disclosure until the maintainer has acknowledged the report and agreed on a
timeline.

## Security boundary

The library validates JSONL structure and the batch/predictor cardinality
contract. It does not authenticate callers, authorize file access, isolate the
predictor, remove sensitive fields, detect malicious content, or provide a
network service. Integrators remain responsible for least privilege, data
minimization, resource limits, and deployment security.

## Supported versions

No stable supported release exists yet. Security fixes apply to the latest
development commit until a versioning policy is adopted.
