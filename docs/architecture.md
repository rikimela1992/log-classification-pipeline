# Architecture

## Scope

The current release candidate is a model-independent boundary for synthetic or
already-sanitized JSONL batches. It is intentionally limited to parsing,
validation, orchestration, and output publication.

## Components

| Component | Responsibility | Failure behavior |
|---|---|---|
| jsonl.py | Decode UTF-8, reject invalid JSON constructs, retain valid records, compute input identity | Collect validation issues and reject the whole batch |
| contracts.py | Validate stable input fields and predictor output mappings | Return line-specific issues or raise a predictor contract error |
| batch.py | Validate before prediction, chunk records, enforce one output per input | Stop before publication if input or predictor behavior is invalid |
| atomic.py | Encode JSONL, sync a temporary file, publish, sync the directory | Remove pre-publication temporary files; distinguish committed failures |

## Processing sequence

1. Read the complete input as bytes and calculate its SHA-256 digest.
2. Decode UTF-8 and parse every non-blank JSONL line with duplicate-key and
   non-finite-number rejection.
3. Aggregate all input issues. If any issue exists, reject the complete batch
   before invoking the predictor.
4. Call the predictor in bounded chunks and materialize each chunk result.
5. Require exactly one mapping with string keys for each input record.
6. Encode every validated prediction to a temporary file in the destination
   directory.
7. Flush and sync the file, publish it without overwrite by default, then sync
   the parent directory.

## Publication states

| State | Destination visible | Cleanup behavior | Caller signal |
|---|---:|---|---|
| Parsing/prediction failure | no | no output created | validation or predictor exception |
| Temporary write failure | no | temporary file removed when possible | original exception |
| Publication failure | no | temporary file removed when possible | filesystem exception |
| Directory-sync failure | yes | destination is not falsely rolled back | PublicationDurabilityError |
| Temporary-link cleanup failure | yes | committed state is explicit | PublicationCleanupError |

## Trust boundaries

Input records and predictor output are untrusted. Structural validation does not
make arbitrary fields safe to store or disclose. The predictor runs in the
caller's process and is outside this library's security boundary. Destination
filesystem semantics are deployment assumptions that must be validated by an
integrator.

## Deliberate exclusions

The candidate contains no network service, model adapter, model artifact,
training code, dataset, production log, deployment manifest, infrastructure
identifier, or secret-management integration.
