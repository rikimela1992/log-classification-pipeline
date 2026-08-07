# Log Classification Pipeline

## Project status

This repository contains the alpha batch-processing foundation for a future log
classification pipeline. It is **not production-ready**. The planned first
release is `v0.1.0-alpha.1`, titled **Fail-closed batch-processing foundation**.
The project is available under the [MIT License](LICENSE).

All examples and test records are synthetic. This repository includes no model,
checkpoint, tokenizer, dataset, production log, or operational configuration.
A Transformers adapter is not part of this public foundation.

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

## Architecture

![Fail-closed batch pipeline](docs/assets/pipeline-overview.svg)

The package is organized into strict JSONL parsing, input/output contracts,
batch orchestration, and atomic publication helpers. See
[docs/architecture.md](docs/architecture.md) for component boundaries and
failure semantics.

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

Python 3.12 or newer is required. The current foundation has no third-party
runtime dependencies.

    python3 -m venv .venv
    .venv/bin/python -m pip install --no-deps .

## Synthetic example

Validate the included synthetic examples without invoking a model:

    PYTHONPATH=src python3 examples/validate.py examples/input-valid.jsonl
    PYTHONPATH=src python3 examples/validate.py examples/input-invalid.jsonl

The first command exits with status 0. The second command reports a validation
failure and exits non-zero. It does not create output or call a predictor.

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

- There is no Transformers adapter, model loading, training, or inference CLI.
- Input is read and validated in memory. Resource limits are opt-in and no
  default operational profile is claimed.
- Atomicity and durability behavior is designed for local POSIX-like
  filesystems and is not claimed for every network filesystem or operating
  system.
- The predictor is supplied by the caller and runs in-process without isolation.
- The input schema is intentionally small and has no explicit schema-version
  negotiation yet.
- This project has not completed production hardening, load testing, or an
  independent security review.

## Roadmap

1. Define measured operational profiles and evaluate conservative default limits.
2. Define a versioned predictor adapter contract.
3. Add a Transformers adapter only after artifact provenance and offline
   reproducibility requirements are documented and tested.
4. Add end-to-end synthetic equivalence fixtures and performance measurements.
5. Review cross-platform publication semantics and document supported
   filesystems.
6. Validate CI, then prepare the planned v0.1.0-alpha.1 release without changing
   the foundation scope.
