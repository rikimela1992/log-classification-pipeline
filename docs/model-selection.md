# Experimental model selection

## Decision

The default experimental adapter uses
[`MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c`](https://huggingface.co/MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c)
at revision
`bddf8c5411c34ac3565e16e04384fd68b2618dda`.

This is a compact natural-language-inference encoder, not a chat model. It can
rank candidate labels without project-specific training examples, which makes
it useful for testing the end-to-end contract before a trustworthy labelled
dataset exists. The commercial-friendly variant reports an MIT license and
ships `safetensors` weights.

## Why not generic DistilBERT or DeBERTa?

A generic base checkpoint is trained for language representation, not directly
for zero-shot classification. It needs a suitable NLI/classification head or
project-specific fine-tuning. Choosing a named NLI checkpoint makes the intended
task and provenance explicit.

## Smaller fallback

[`cross-encoder/nli-MiniLM2-L6-H768`](https://huggingface.co/cross-encoder/nli-MiniLM2-L6-H768)
is the planned CPU-oriented comparison. Its Apache-2.0 model card exposes
PyTorch, ONNX, and OpenVINO artifacts. It is not the default until both models
are measured on the same independently authored fixture.

## Artifact policy

- No model, tokenizer, cache, or downloaded metadata is committed.
- The default revision is a complete immutable commit hash.
- Local loading is the default; network download requires
  `--allow-download`.
- Remote model code is disabled and `safetensors` is required.
- A local directory requires `--model-source`, `--model-id`, and
  `--model-revision`. These local metadata are caller-declared and are not
  verified against directory contents; an artifact hash manifest is still
  planned.
- Offline deployment should set `HF_HUB_OFFLINE=1` and
  `TRANSFORMERS_OFFLINE=1`.

The Transformers documentation describes
[offline mode and local files](https://huggingface.co/docs/transformers/en/installation#offline-mode).

## Known risks

- The selected model is primarily English-oriented.
- NLI cost grows with records multiplied by candidate labels.
- Scores depend on candidate wording and the hypothesis template.
- Scores are not calibrated probabilities and do not create a true unknown
  class; the adapter therefore exposes an explicit abstention threshold.
- Technical logs may differ strongly from the model's training domain.
- Input minimization remains the caller's responsibility.
