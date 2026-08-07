# Architecture

## Scope

The current release candidate is a model-independent boundary for synthetic or
already-sanitized JSONL batches. It is intentionally limited to parsing,
validation, orchestration, and output publication.

![Fail-closed batch pipeline](assets/pipeline-overview.svg)

## Components

| Component | Responsibility | Failure behavior |
|---|---|---|
| jsonl.py | Enforce optional byte/record limits, decode UTF-8, reject invalid JSON constructs, retain valid records, compute input identity | Reject a limit breach or collect validation issues and reject the whole batch |
| contracts.py | Validate stable input fields and predictor output mappings | Return line-specific issues or raise a predictor contract error |
| batch.py | Validate before prediction, chunk records, consume at most one excess output, enforce one output per input | Stop before publication if input or predictor behavior is invalid |
| atomic.py | Encode JSONL, apply permissions, sync a temporary file, publish, sync the directory | Attempt pre-publication temporary cleanup; distinguish committed failures |

## Processing sequence

1. Read the input with an optional byte bound and calculate its SHA-256 digest.
2. Decode UTF-8 and parse LF-delimited, non-blank JSONL lines with duplicate-key and
   non-finite-number rejection.
3. Enforce an optional non-blank record-line bound and aggregate input issues.
   If a limit or validation issue occurs, reject the complete batch before
   invoking the predictor.
4. Call the predictor in bounded chunks and consume at most `chunk size + 1`
   results.
5. Require exactly one mapping with string keys for each input record.
6. Validate and encode each predictor chunk while staging a temporary file in
   the destination directory.
7. Flush, apply the requested mode, and sync the file; publish it without
   overwrite by default; then sync the parent directory.

## Publication states

![Atomic publication state machine](assets/publication-state-machine.svg)

| State | Destination visible | Cleanup behavior | Caller signal |
|---|---:|---|---|
| Parsing/prediction failure | no | temporary file removed when possible; no destination published | validation or predictor exception |
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
