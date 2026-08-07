# Synthetic evaluation — 2026-08-07

## Scope

This is a reproducible smoke test of the public taxonomy and application path.
It is **not** evidence of production accuracy. The fixture contains 11 short,
handwritten English messages designed for this repository. It contains no real
logs, operational identifiers, organizations, addresses, or dataset history.

## Results

| Predictor | Subsystem accuracy | Subsystem macro-F1 | Severity accuracy | Severity macro-F1 | Coverage at 0.60 |
|---|---:|---:|---:|---:|---:|
| Synthetic rules baseline | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| DeBERTa zero-shot | 1.000 | 1.000 | 0.727 | 0.448 | 0.182 |

The rules result only confirms that the deliberately aligned fixture reaches
every taxonomy class and exercises the evaluation wiring. It must not be
interpreted as model quality.

The zero-shot result is more informative: subsystem routing was promising on
this tiny fixture, while severity wording and calibration were not. Nine of
eleven records abstained at the conservative 0.60 threshold. Accuracy and
macro-F1 above are calculated over all records, including abstentions.

## Local CPU measurement

The zero-shot run used an isolated, network-disabled Linux container with four
CPU cores available and an 8 GiB memory limit:

- Python 3.12.3;
- Transformers 4.48.0;
- PyTorch 2.4.1, CPU execution;
- 11 records in one evaluation call;
- 9.07 seconds wall-clock, including model load;
- 8.48 seconds measured inside evaluation;
- 1.298 records/second;
- 1,680,792 KiB maximum resident set size.

This is a single cold run, not a latency benchmark. Hardware, scheduling,
library versions, taxonomy size, and label wording materially affect it.

## Reproduction

After placing the pinned model in a local directory:

    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 PYTHONPATH=src python3 -m \
      log_classification_pipeline.cli evaluate \
      tests/fixtures/synthetic-evaluation.jsonl \
      --adapter zero-shot --model-source <local-model-directory> \
      --model-id MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c \
      --model-revision bddf8c5411c34ac3565e16e04384fd68b2618dda

Reproduction additionally requires the exact model artifacts and declared
dependencies. The committed fixture and evaluator are included; model files are
intentionally excluded.
