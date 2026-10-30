# Changelog

All notable release changes are recorded here. The project follows semantic
versioning once a stable compatibility policy is adopted; alpha releases may
still change interfaces.

## Unreleased

- Serialize job state transitions so cancellation cannot be lost or leave a job
  stuck in `cancelling`.
- Raise the scrypt cost to N=2^17 and upgrade stored hashes on successful login.
- Delete expired sessions for real when they are presented.
- Keep the login page's token on `429`/`401`, and let its locale form work with
  any session cookie.
- Make the login limiter count attempts atomically before they run.
- Add the admin-only `GET /api/v1/jobs/{id}/raw` and refuse `--store-raw` above
  its cap before classification.
- Audit job reads as `job.view`; `job.export` now means an actual download.
- Return `413` for oversized chunked bodies and `422` for over-nested JSONL.
- Reject input when the queue is full before parsing it.
- Try-restart an active service on Debian and RPM upgrades.

## 0.1.0-alpha.2 — 2026-10-30

- Add CI quality, coverage, dependency-audit, and dependency-review gates.
- Add provenance attestations and separate public/full checksum manifests.
- Add repository ownership, contribution, issue, and pull-request guidance.
- Move repository, package metadata, and AppStream identifiers to `silirim`.
- Audit only the released surfaces; Gradio's Pillow cap keeps `ui` and `demo` out.
- Add admin user updates: role, disabled state, password reset, and session revocation.
- Keep a failed first setup from leaving an empty workspace that blocks login.
- Restore the language selector under the content security policy.
- Remove the Swagger page, which that policy cannot render; OpenAPI JSON remains.

## 0.1.0-alpha.1 — 2026-08-08

- Publish the fail-closed batch core, authenticated local workspace, web UI,
  CLI, experimental model profiles, and four x86-64 Linux package formats.
