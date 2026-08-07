# Multilingual development smoke baseline — 2026-08-07

## Scope

This is a deterministic wiring result for the dependency-free rules adapter,
not a multilingual model benchmark. The committed fixture has 40 handwritten,
synthetic messages: ten each in English, Italian, French, and Spanish. Every
language includes every subsystem once and the same balanced severity pattern.
It contains no real logs, organizations, addresses, hosts, or operational
paths. The fixture is a public development set and is not an independent
holdout.

## Results

| Language | Coverage | Subsystem accuracy | Severity accuracy | Joint accuracy |
|---|---:|---:|---:|---:|
| English | 1.000 | 1.000 | 0.400 | 0.400 |
| Italian | 0.600 | 0.600 | 0.300 | 0.300 |
| French | 0.300 | 0.300 | 0.000 | 0.000 |
| Spanish | 0.100 | 0.100 | 0.100 | 0.100 |
| **Overall** | **0.500** | **0.500** | **0.200** | **0.200** |

Overall subsystem macro-F1 was `0.643810`; severity macro-F1 was `0.246869`.
Among accepted records, subsystem accuracy was `1.000` and severity accuracy
was `0.400`. The maximum language gaps were 0.900 for coverage and subsystem
accuracy, and 0.400 for severity and joint accuracy.

These poor and uneven results are expected: the rules adapter recognizes a
small English keyword vocabulary and exists only to verify wiring. They provide
a useful negative baseline and demonstrate why UI translation alone does not
make classification multilingual.

## Reproduction

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m \
  log_classification_pipeline.cli evaluate \
  tests/fixtures/synthetic-evaluation-multilingual.jsonl --adapter rules
```

The evaluator validates language tags, reports per-language and worst-language
metrics, counts abstentions as end-to-end errors, and reports selective
accuracy separately. It rejects mixed splits and model/configuration
provenance, and emits the fixture version, split, and complete model provenance.
The pinned `multilingual-bge-m3-v1` profile has not yet
been executed here because this host has no GPU and only about 6.8 GiB of
available memory; model weights alone are approximately 1.14 GB. No model
quality result is claimed until a controlled CPU or GPU run is recorded.
