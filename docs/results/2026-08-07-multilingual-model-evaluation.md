# Multilingual model evaluation — 2026-08-07

## Scope

This is an alpha capacity and development-quality result, not a deployment
benchmark. The public `multilingual-smoke-v1` fixture contains 40 synthetic,
handwritten messages: ten each in English, Italian, French, and Spanish. It is
a development set close to the public taxonomy, not an independent holdout.

All model artifacts remained outside the repository. Inference ran offline
with two CPU inference threads on four QEMU/KVM vCPUs, 7.8 GiB RAM, Python
3.13.5, PyTorch 2.13.0+cpu, Transformers 5.14.1, and SentencePiece 0.2.2.

## Fast MiniLM profile

`multilingual-minilm-v1` resolves to
`MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli` at immutable revision
`0a71e92a985b6e1ad1828cf67ce9c459639c1dca`. The local `safetensors` file was
427,997,022 bytes with SHA-256
`91b323ccf247ec1e3b5925d566230bae7c52de8147e6062b42e250089a3fc80b`.
The model configuration reports six layers and hidden size 384. Eight
downloaded files were checked against the pinned Hub revision; omitted ONNX and
legacy PyTorch artifacts were not required for this Transformers run.

At the conservative default threshold `0.60`, all 40 predictions abstained.
The run completed in 11.578666 seconds, or 3.455 records/second. This is correct
fail-closed behavior, but zero operational coverage.

One additional run at threshold zero measured raw top-label quality without
claiming calibration:

| Language | Subsystem accuracy | Severity accuracy | Joint accuracy |
|---|---:|---:|---:|
| English | 0.700 | 0.400 | 0.300 |
| Italian | 0.600 | 0.400 | 0.300 |
| French | 0.600 | 0.100 | 0.100 |
| Spanish | 0.500 | 0.300 | 0.300 |
| **Overall** | **0.600** | **0.300** | **0.250** |

Overall subsystem macro-F1 was `0.565518`; severity macro-F1 was `0.265299`.
The run completed in 11.344725 seconds, or 3.526 records/second. The threshold
zero result must not be interpreted as a safe operating configuration: it
forces acceptance and was measured on the development fixture.

## Balanced mDeBERTa profile

`multilingual-mdeberta-v1` resolves to
`MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7` at immutable
revision `b5113eb38ab63efdd7f280f8c144ea8b13f978ce`. Its 557,652,046-byte
`safetensors` file had SHA-256
`7c8e29f1115986d032e92b0fbaa0bdef1062a46f658b08705f237c05014a8541`.
The artifact loaded all 202 tensors offline.

A single cold synthetic English record took 34.371922 seconds and reached
825,240 KiB maximum resident memory. The prediction abstained at threshold
`0.60`. A full 40-record run produced no metrics after the predeclared ten
checks over approximately five minutes and was interrupted. No partial result
was treated as success.

## Decision

- MiniLM is registered as a fast **experimental** CPU profile, not the default.
- mDeBERTa is registered as a balanced **experimental** asynchronous profile.
- BGE-M3 remains a quality-first **experimental** GPU profile.
- No model is accuracy-qualified or production-ready.
- The next quality gate requires a larger development set for separate
  subsystem/severity calibration and an independently authored holdout.
