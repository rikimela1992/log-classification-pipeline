# Synthetic examples

Every record in this directory is invented for this repository. The files do
not contain production logs, copied messages, real infrastructure identifiers,
or model labels.

Run the valid example:

    PYTHONPATH=src python3 examples/validate.py examples/input-valid.jsonl

Run the deliberately invalid example:

    PYTHONPATH=src python3 examples/validate.py examples/input-invalid.jsonl

The invalid file contains one blank required field and one malformed JSON line.
Validation is expected to fail with a non-zero exit status before any predictor
could be called.
