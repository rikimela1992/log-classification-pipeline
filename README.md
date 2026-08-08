# Log Classification Pipeline

Local, fail-closed log classification with a browser dashboard, API, CLI, and
exportable results.

> **Alpha:** this project is not production-ready. It is designed for local,
> bounded analysis and does not ship logs, datasets, model weights, or default
> credentials.

![Authenticated dashboard with synthetic data](docs/assets/dashboard-preview.png)

## What it does

- Accepts `.jsonl`, `.ndjson`, `.txt`, `.log`, and `.csv` files.
- Validates the complete file before classification starts.
- Classifies subsystem and severity without copying the source message into the
  result.
- Provides an authenticated local dashboard with admin, analyst, and viewer
  roles.
- Supports English, Italian, French, and Spanish in the browser interface.
- Exports completed results and records privacy-minimal audit events.
- Publishes a batch only when every input and prediction passes validation.

The default rules adapter works offline and requires no model download.
Experimental zero-shot model profiles are available separately for English and
multilingual analysis.

## Install on Linux

Download the preferred file from [GitHub Releases](https://github.com/rikimela1992/log-classification-pipeline/releases):

| Package | Intended use |
| --- | --- |
| AppImage | Portable desktop launch |
| `.deb` | Ubuntu 24.04+ and Debian 13 |
| `.rpm` | Fedora 41+ |
| `.tar.gz` | Portable archive or server setup |

The first desktop launch guides you through creating a private workspace,
administrator account, and password. The application then opens locally at
`http://127.0.0.1:8080/app`.

Packages contain the web workspace and offline rules baseline, but no model,
tokenizer, Transformers, PyTorch, or dataset. Alpha artifacts have SHA-256
checksums and SBOMs but are not cryptographically signed.

See [Linux packages](docs/linux-packages.md) for installation, checksum
verification, and optional systemd activation.

## Input formats

| Format | Expected content |
| --- | --- |
| JSONL / NDJSON | One JSON object per line with a non-blank `message` field |
| TXT / LOG | One message per non-blank line |
| CSV | A unique header containing the exact `message` column |

Quoted CSV fields and embedded newlines are supported. The CLI and web app use
an alpha limit of 25 MiB and 25,000 records per file; the local web queue admits
at most 50 MiB across running and queued jobs.

Malformed input, invalid UTF-8, duplicate JSON keys, inconsistent CSV rows,
predictor failures, and result-count mismatches fail closed. No partial result
is published.

![Fail-closed batch pipeline](docs/assets/pipeline-overview.svg)

## Models

`rules` is the safe initial choice: deterministic, offline, and bundled.
Optional profiles include a pinned English DeBERTa NLI encoder and experimental
multilingual encoders covering English, Italian, French, and Spanish.

Model downloads are disabled by default. Local model directories require a
verified manifest and remain outside this repository. Current multilingual
results are development measurements, not accuracy or production claims.

See [model selection](docs/model-selection.md) and
[evaluation results](docs/results/2026-08-07-multilingual-model-evaluation.md).

## Python and development

Python 3.12 or newer is required.

```console
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps .
.venv/bin/log-classify doctor
```

Install the authenticated web interface and initialize a workspace:

```console
.venv/bin/python -m pip install '.[web]'
.venv/bin/log-classify workspace init ./state/workspace.sqlite3 sample-org owner
.venv/bin/log-classify web ./state/workspace.sqlite3
```

Passwords are prompted interactively and are never accepted as command-line
arguments.

Run the full test suite:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python3 -m unittest discover -s tests -v
```

Validate the included synthetic examples without invoking a model:

```console
PYTHONPATH=src python3 examples/validate.py examples/input-valid.jsonl
PYTHONPATH=src python3 examples/validate.py examples/input-invalid.jsonl
```

## Documentation

| Topic | Document |
| --- | --- |
| Architecture and atomic publication | [Architecture](docs/architecture.md) |
| Local accounts, roles, retention, and export | [Local workspace](docs/local-workspace.md) |
| Browser UI, API, queue, and security boundaries | [Web workspace](docs/web-workspace.md) |
| Linux packages and first launch | [Linux packages](docs/linux-packages.md) |
| Model profiles and artifact verification | [Model selection](docs/model-selection.md) |
| Security reporting | [Security policy](SECURITY.md) |
| Measured validation evidence | [Results](docs/results/) |

## Security and limitations

- The browser and API bind only to loopback; remote deployment is unsupported.
- The SQLite workspace is local and supports one organization per database.
- Inputs are processed in memory and the predictor runs in-process.
- The queue and login limiter are process-local and reset on restart.
- The database is not encrypted and secure deletion cannot cover backups,
  snapshots, swap, or copy-on-write storage.
- Zero-shot scores are experimental and are not calibrated probabilities.
- Atomic publication targets local POSIX-like filesystems.
- Production hardening, load testing, SSO, distributed workers, and an
  independent security review are still pending.

All examples and screenshots use synthetic data. Do not add real logs,
credentials, infrastructure identifiers, model weights, or operational
configuration to this repository.

## License

[MIT License](LICENSE) — Copyright (c) 2026 Riccardo Melini.
