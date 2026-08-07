# Log Classification Pipeline

## Project status

This repository contains the alpha batch-processing foundation for a future log
classification pipeline. It is **not production-ready**. The planned first
release is `v0.1.0-alpha.1`, titled **Fail-closed batch-processing foundation**.
The project is available under the [MIT License](LICENSE).

All examples and test records are synthetic. This repository includes no model,
checkpoint, tokenizer, dataset, production log, or operational configuration.
An optional, offline-first zero-shot adapter is included, but model artifacts
remain outside the repository.

## Problem

Batch classifiers can create dangerous ambiguity when they skip malformed
records, publish partial output, or report success after processing only part of
an input. Downstream automation may then treat incomplete results as complete.

This foundation establishes a strict boundary before a model adapter is called.
It validates the entire input, enforces a one-input/one-output contract, and
publishes output only after every result has passed validation.

## Design goals

- Fail closed on malformed input or predictor contract violations.
- Never silently publish a partial batch.
- Preserve the exact input identity with a SHA-256 digest.
- Avoid overwriting existing output unless explicitly requested.
- Make post-publication durability failures distinguishable from failures that
  occur before a destination becomes visible.
- Keep the core independent from any model framework.
- Make the model adapter and local UI optional, lazy-loaded extras.
- Emit privacy-minimal classifications without echoing input messages.

## Architecture

![Fail-closed batch pipeline](docs/assets/pipeline-overview.svg)

The package is organized into strict JSONL parsing, input/output contracts,
batch orchestration, and atomic publication helpers. See
[docs/architecture.md](docs/architecture.md) for component boundaries and
failure semantics.

![Optional model and interface path](docs/assets/model-evaluation-loop.svg)

The CLI and local UI call the same fail-closed application services.

An optional local authenticated workspace now adds an offline consult-and-export
flow with separate admin, analyst, and viewer roles. It uses a private SQLite
database, retains raw source bytes only when explicitly requested, and applies
separate retention periods to raw data, results, and audit events. See the
[local workspace guide](docs/local-workspace.md). It is not a remotely exposed
multi-tenant service.

## Fail-closed batch contract

Every non-blank input line must be a UTF-8 JSON object with a non-blank
message string. Duplicate object keys, non-finite numbers, malformed JSON,
invalid optional field types, and scalar top-level values are rejected.

The complete input is parsed and validated before the predictor is called. The
predictor must then return exactly one mapping for every input record. If any
chunk fails or returns the wrong number of results, output publication does not
start. Predictor iterables are consumed only through the first excess result,
so cardinality checks do not materialize unbounded overproduction.

Unknown fields are preserved and passed to the predictor. The caller remains
responsible for data minimization before invoking the library.

## Resource bounds

`read_jsonl` and `process_batch` accept positive `max_input_bytes` and
`max_records` limits. The byte limit is enforced while reading at most one
byte beyond the boundary. The record limit counts non-blank JSONL lines and
fails on the first excess line. Either failure occurs before predictor
invocation.

Limits default to `None` to avoid inventing an operational policy for callers
in this alpha. Applications processing untrusted data should set both values;
the package remains an in-memory batch foundation rather than a streaming
parser.

## Atomic output publication

Output is encoded into a temporary file in the destination directory. The file
is flushed and synced before publication. Output permissions default to
`0o600` and can be changed explicitly with `output_mode`. By default, an
existing destination is not replaced. The directory is synced after the
destination becomes visible.

Failures before publication attempt to remove the temporary file. Failures
after the destination becomes visible raise a dedicated committed-publication
exception, so callers are not told that an already visible output was rolled back.

## Installation

Python 3.12 or newer is required. The core has no third-party runtime
dependencies. Model and UI dependencies are optional.

    python3 -m venv .venv
    .venv/bin/python -m pip install --no-deps .

For the local rules-based wiring demo:

    PYTHONPATH=src python3 -m log_classification_pipeline.cli evaluate tests/fixtures/synthetic-evaluation.jsonl

For the local UI:

    .venv/bin/python -m pip install '.[ui]'
    .venv/bin/log-classify ui

For the authenticated local workspace:

    .venv/bin/log-classify workspace init ./state/workspace.sqlite3 sample-org owner
    .venv/bin/log-classify workspace classify \
      ./state/workspace.sqlite3 sample-org owner examples/input-valid.jsonl
    .venv/bin/log-classify workspace jobs \
      ./state/workspace.sqlite3 sample-org owner

Passwords are prompted interactively. The workspace has no default credentials
and does not accept passwords as command-line arguments.

For zero-shot inference:

    .venv/bin/python -m pip install '.[ml]'
    .venv/bin/log-classify classify input.jsonl output.jsonl --adapter zero-shot \
      --model-source /path/to/local/model --model-id <declared-model-id> \
      --model-revision <declared-revision>

Downloads are disabled by default. Pass `--allow-download` only when network
access and the pinned model provenance are acceptable.

## Synthetic example

Validate the included synthetic examples without invoking a model:

    PYTHONPATH=src python3 examples/validate.py examples/input-valid.jsonl
    PYTHONPATH=src python3 examples/validate.py examples/input-invalid.jsonl

The first command exits with status 0. The second command reports a validation
failure and exits non-zero. It does not create output or call a predictor.

## Experimental model adapter

The default experimental encoder is
[`MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c`](https://huggingface.co/MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c),
pinned to a full commit revision. It is an NLI encoder used for zero-shot
classification, not a generative LLM. The public taxonomy has ten subsystem
labels and five severity labels. Predictions include labels, scores, abstention,
and model provenance; they do not copy the source message.

See [model selection](docs/model-selection.md) for the rationale and
[synthetic evaluation results](docs/results/2026-08-07-synthetic-evaluation.md)
for the first honest, deliberately small measurement.

## Running tests

    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
      python3 -m unittest discover -s tests -v

The suite covers strict parsing, aggregate validation errors, predictor count
mismatches, exceptions in later chunks, symlink and path aliases, overwrite
behavior, resource-limit boundaries, Unicode JSONL separators, bounded predictor
output, atomic cleanup, and post-publication durability errors.

## Security and privacy

- Every bundled example and fixture is synthetic.
- No real logs, infrastructure identifiers, credentials, datasets, or model
  artifacts belong in this repository.
- Input is treated as untrusted structured data; validation happens before model
  invocation.
- The library does not redact arbitrary user fields. Applications must minimize
  and sanitize data before processing.
- Existing destinations are protected from overwrite by default.
- Security reports should follow [SECURITY.md](SECURITY.md).

## Current limitations

- The zero-shot adapter is experimental and English-oriented; its scores are not
  calibrated probabilities.
- Model artifacts and optional dependencies are not bundled.
- The UI binds only to localhost and is a demonstration, not an authenticated
  service.
- The authenticated workspace is local CLI infrastructure for one organization
  per SQLite database. It is not an HTTP API, remotely accessible UI, SSO
  integration, or production multi-tenant isolation boundary.
- Workspace database permissions and SQLite secure deletion do not provide
  encryption at rest or guarantee erasure from backups, snapshots, SSDs, or
  copy-on-write storage.
- Input is read and validated in memory. Resource limits are opt-in and no
  default operational profile is claimed.
- Atomicity and durability behavior is designed for local POSIX-like
  filesystems and is not claimed for every network filesystem or operating
  system.
- The predictor is supplied by the caller and runs in-process without isolation.
- The classification taxonomy is versioned, but input schema negotiation is not
  implemented.
- This project has not completed production hardening, load testing, or an
  independent security review.

## Roadmap

1. Define measured operational profiles and evaluate conservative default limits.
2. Calibrate abstention and severity labels on a larger, independently authored
   synthetic evaluation set.
3. Benchmark the smaller MiniLM fallback and measure warm/cold CPU behavior.
4. Add an explicit artifact manifest and cache verification workflow.
5. Review cross-platform publication semantics and document supported
   filesystems.
6. Add a separately threat-modelled HTTP API and authenticated web interface;
   keep network exposure disabled until CSRF, rate limits, TLS deployment, and
   integration tests exist.
7. Validate CI, then prepare the planned v0.1.0-alpha.1 release without changing
   the foundation scope.
