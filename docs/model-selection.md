# Experimental model selection

## Versioned profiles

The default experimental English profile, `english-deberta-v1`, uses
[`MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c`](https://huggingface.co/MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c)
at revision
`bddf8c5411c34ac3565e16e04384fd68b2618dda`.

This is a compact natural-language-inference encoder, not a chat model. It can
rank candidate labels without project-specific training examples, which makes
it useful for testing the end-to-end contract before a trustworthy labelled
dataset exists. The commercial-friendly variant reports an MIT license and
ships `safetensors` weights.

The opt-in multilingual profile, `multilingual-bge-m3-v1`, uses
[`MoritzLaurer/bge-m3-zeroshot-v2.0-c`](https://huggingface.co/MoritzLaurer/bge-m3-zeroshot-v2.0-c)
at revision `705510dfe0f35d223a4bf6f5d2695ec5fd162341`. Its model card
describes the `-c` checkpoint as multilingual, commercial-friendly, MIT
licensed, and recommends it over the English checkpoints for multilingual
input. The current artifact is approximately 1.14 GB before runtime memory.

Both profiles currently use English candidate descriptions and hypothesis
templates. Profile IDs, profile revisions, resolved model identity,
prompt/candidate configuration, batch size, and both abstention thresholds
contribute to a SHA-256 configuration digest emitted with each prediction.

The multilingual profile covers English, Italian, French, and Spanish.
“Covers” means the selected NLI checkpoint supports those languages and the
software path is wired; it is **not** an accuracy claim.

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
- Prompt and candidate behavior is selected by a versioned profile and
  represented by a deterministic configuration digest.
- Local loading is the default; network download requires
  `--allow-download`.
- Remote model code is disabled and `safetensors` is required.
- A local directory requires `--model-source`, `--model-id`, and
  `--model-revision`. ID and revision must match the selected registered
  profile. They are not verified against directory contents; an artifact hash
  manifest is still planned.
- Offline deployment should set `HF_HUB_OFFLINE=1` and
  `TRANSFORMERS_OFFLINE=1`.

The Transformers documentation describes
[offline mode and local files](https://huggingface.co/docs/transformers/en/installation#offline-mode).

## Selecting a profile

Known profiles can be resolved from the Hub only with explicit permission:

```console
log-classify evaluate tests/fixtures/synthetic-evaluation-multilingual.jsonl \
  --adapter zero-shot --model-profile multilingual-bge-m3-v1 --allow-download
```

For offline use, pass a local directory plus the exact identity and revision of
the selected profile. `--subsystem-threshold` and `--severity-threshold` can
override the shared `--confidence-threshold`; resolved values enter the
configuration digest.

The authenticated web selector can expose both profiles lazily:

```console
log-classify web ./state/workspace.sqlite3 \
  --enable-model-profile english-deberta-v1 \
  --enable-model-profile multilingual-bge-m3-v1
```

Downloads remain disabled unless `--allow-download` is also supplied.

## Known risks

- DeBERTa is English-oriented; BGE-M3 is larger and has not yet been measured
  on the committed multilingual fixture.
- NLI cost grows with records multiplied by candidate labels.
- Scores depend on candidate wording and the hypothesis template.
- Scores are not calibrated probabilities and do not create a true unknown
  class; the adapter therefore exposes an explicit abstention threshold.
- Technical logs may differ strongly from the model's training domain.
- Input minimization remains the caller's responsibility.
- A 40-row synthetic development fixture can detect wiring regressions but is
  too small and too close to the public taxonomy to authorize deployment.
