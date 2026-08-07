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

## BGE-M3 CPU capacity probe

The pinned `multilingual-bge-m3-v1` artifact was downloaded to a temporary
directory at revision `705510dfe0f35d223a4bf6f5d2695ec5fd162341`. The six
files required for local inference were checked with `hf cache verify`; model
weights and tokenizer data remain outside the repository. Transformers loaded
all 393 weight tensors successfully with downloads disabled.

The same 40-record fixture was then started as a cold, offline CPU run. It did
not complete after more than five minutes of inference and was interrupted at
the predeclared ten-check limit. No exception occurred, but no partial metrics
were emitted by the fail-closed evaluator. The measured environment was:

- 4 KVM virtual CPU cores and no GPU;
- 7.8 GiB RAM plus 4.1 GiB swap;
- Python 3.13.5, PyTorch 2.13.0+cpu, and Transformers 5.14.1;
- two inference threads;
- a 1,135,561,748-byte `model.safetensors` file.

This is a capacity result, not a model-quality result. It shows that the current
0.6-billion-parameter BGE-M3 profile is unsuitable for a synchronous,
interactive CPU path on this host. It remains available as an explicit
quality-first experiment for GPU or asynchronous batch execution. A smaller
multilingual CPU profile must be benchmarked before one is offered as an
interactive default. No accuracy, F1, latency-per-record, or throughput value
can be reported from an interrupted run.
