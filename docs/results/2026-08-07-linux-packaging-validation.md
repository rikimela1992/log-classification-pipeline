# Linux packaging validation — 2026-08-07

## Scope

This is a local pre-release build validation, not a compatibility certification
or a production deployment assessment. No tag or GitHub release was created.
The build used the repository's rules-only packaging profile and included no
model, tokenizer, dataset, Transformers runtime, or PyTorch runtime.
Candidate files are checksummed but are not cryptographically signed in this
alpha validation.

## Local results

| Check | Result |
| --- | --- |
| PyInstaller 6.18.0 one-directory build | passed |
| Frozen `doctor --require web` smoke test | passed |
| Frozen bundle size on the local Debian 13 host | approximately 31 MiB |
| Deterministic Python-runtime CycloneDX inventory | generated and parsed |
| Syft 1.50.0 frozen-bundle SPDX inventory | generated and parsed |
| Self-contained `.tar.gz` construction | passed |
| Debian control/archive construction | passed |
| Extracted DEB frozen-runtime smoke test | passed |
| AppImage construction and extracted-runtime smoke test | passed |
| Shell syntax and package-file tests | passed |
| Complete test suite with web extras | 173 tests passed |
| Core-only test suite | 143 passed; 30 web tests intentionally skipped |

The local DEB was approximately 13 MiB and the AppImage approximately 15 MiB.
Their exact bytes and digests are not release evidence because the public
candidates are built separately on the declared GitHub Actions runners.

## CI gate still required

The `linux release candidate` workflow builds portable/DEB/AppImage artifacts
on Ubuntu 24.04 and an RPM in Fedora 41, smoke-tests the native frozen bundles,
merges them only after both jobs pass, and then generates a combined
`SHA256SUMS`. The workflow has read-only repository permissions and cannot
publish a release.

The RPM is therefore not reported as locally validated in this document. The
local AppImage check validates the packaging path, but the distributable
Ubuntu-built AppImage and Fedora-built RPM become release evidence only after
the GitHub packaging workflow passes and its artifacts have been inspected.
