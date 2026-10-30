# Changelog

All notable release changes are recorded here. The project follows semantic
versioning once a stable compatibility policy is adopted; alpha releases may
still change interfaces.

## Unreleased

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
