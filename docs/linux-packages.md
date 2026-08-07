# Self-contained Linux packages

## Status and scope

The release-candidate workflow builds four x86-64 Linux formats without
publishing them automatically:

| Format | Intended alpha target | Installation style |
| --- | --- | --- |
| `.deb` | Ubuntu 24.04+ and Debian 13 | graphical package installer or APT |
| `.rpm` | Fedora 41+ | graphical software installer or DNF |
| AppImage | compatible modern desktop Linux | mark executable and launch |
| `.tar.gz` | compatible modern Linux | extract and run the bundled launcher |

The binaries are built natively on Ubuntu 24.04 and Fedora 41. They are not
claimed to work on every distribution, CPU architecture, libc, container, or
headless environment. This remains an alpha, localhost-only application and is
not production-ready.

Each candidate contains the Python runtime, CLI, authenticated browser
workspace, static assets, and the deterministic rules baseline. No model,
tokenizer, dataset, Transformers runtime, PyTorch runtime, or model cache is
bundled. Model-enabled packages require a separate future size, license, and
platform review.

## Desktop first launch

Installing the DEB or RPM adds a desktop entry named **Log Classification
Pipeline**. AppImage users can launch the downloaded file directly after their
desktop has allowed execution. The launcher opens a terminal for a one-time,
local setup:

1. choose an organization identifier;
2. choose the first administrator username;
3. enter and confirm a password without placing it in process arguments;
4. start the service on `127.0.0.1:8080` and open the browser when a graphical
   session is available.

Per-user state is stored below
`$XDG_STATE_HOME/log-classification-pipeline`, or
`$HOME/.local/state/log-classification-pipeline` when `XDG_STATE_HOME` is not
set. The directory and SQLite database are private to the operating-system
account. No default credential exists.

The portable archive uses the same launcher:

```console
./log-classification-pipeline-0.1.0-alpha.1-linux-x86_64/usr/bin/log-classification-pipeline
```

## Deliberate server activation

DEB and RPM packages install, but do not automatically enable, a hardened
systemd unit. This avoids exposing a service or inventing credentials during a
non-interactive package installation. Initialize its private workspace once as
the dedicated account, then enable it:

```console
sudo -u log-classify /usr/lib/log-classification-pipeline/log-classify \
  workspace init /var/lib/log-classification-pipeline/workspace.sqlite3 \
  sample-org owner
sudo systemctl enable --now log-classification-pipeline.service
```

The unit still binds only to loopback. Remote or reverse-proxy deployment is
outside the supported alpha profile.

## Integrity and inventory

The final workflow artifact includes `SHA256SUMS`, dependency lock snapshots,
a CycloneDX Python-runtime inventory, a Syft-generated SPDX inventory of the
frozen bundle and native libraries, embedded Python dependency license texts,
the pinned CPython license, and native-library license evidence collected from
the build distribution. For RPM dependencies that install no standalone
license text, the evidence records the package, source RPM, and declared
license expression. Verify all downloaded files before installation:

```console
sha256sum --check --strict SHA256SUMS
```

The AppImage builder and type-2 runtime are fetched from fixed GitHub release
asset IDs and checked against repository-pinned SHA-256 values before use.
GitHub Actions are pinned to commit SHAs. Package CI smoke-tests the frozen web
runtime and inspects or extracts every package format before a candidate is
accepted.

These alpha candidates are checksummed but are not yet cryptographically
signed. Confirm that an archive came from the intended GitHub Actions run, then
verify `SHA256SUMS`, before installing or launching it.

## Building a candidate

Run the **linux release candidate** workflow manually. Its jobs build the
Ubuntu portable/DEB/AppImage set and the native Fedora RPM independently, then
merge them only after both jobs pass. A tag may also trigger the workflow, but
the workflow deliberately has read-only repository permissions and never
creates a tag or release.
