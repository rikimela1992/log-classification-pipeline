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
| Complete test suite with web extras | 174 tests passed |
| Core-only test suite | 144 passed; 30 web tests intentionally skipped |

The local DEB was approximately 13 MiB and the AppImage approximately 15 MiB.
Their exact bytes and digests are not release evidence because the public
candidates are built separately on the declared GitHub Actions runners.

## CI result

The [successful packaging workflow](https://github.com/silirim/log-classification-pipeline/actions/runs/31196447046)
built and smoke-tested the portable archive, DEB, AppImage, and native Fedora
RPM. Its final job merged both build families and verified the combined
`SHA256SUMS` manifest.

The combined artifact was downloaded and independently checked after the run:
all SHA-256 entries passed, all JSON inventories parsed, and all four package
formats were present. The workflow has read-only repository permissions and
cannot itself publish a release.
