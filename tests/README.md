# Synthetic test data

All records, messages, identifiers, paths, and predictor outputs constructed by
the unit tests are synthetic. They are minimal fixtures invented to exercise
validation and publication behavior; they are not derived from production logs,
datasets, infrastructure, users, incidents, or historical model labels.

The suite also covers the local workspace password/session boundary, role
matrix, privacy-minimal audit records, retention boundaries, idempotent purge,
atomic job persistence, symlink refusal, and end-to-end interactive CLI flow.
