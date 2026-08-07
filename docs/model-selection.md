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

The opt-in multilingual profiles have different operational roles:

| Profile | Pinned checkpoint | Intended role | Measured CPU status |
|---|---|---|---|
| `multilingual-minilm-v1` | [`MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli`](https://huggingface.co/MoritzLaurer/multilingual-MiniLMv2-L6-mnli-xnli) | fast CPU experiment | 40 records completed in 11.58 s; quality is insufficient for a default |
| `multilingual-mdeberta-v1` | [`MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7`](https://huggingface.co/MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7) | balanced asynchronous experiment | one cold record took 34.37 s; full run interrupted |
| `multilingual-bge-m3-v1` | [`MoritzLaurer/bge-m3-zeroshot-v2.0-c`](https://huggingface.co/MoritzLaurer/bge-m3-zeroshot-v2.0-c) | quality-first GPU experiment | 40-record CPU run interrupted after five minutes |

The pinned revisions are, respectively,
`0a71e92a985b6e1ad1828cf67ce9c459639c1dca`,
`b5113eb38ab63efdd7f280f8c144ea8b13f978ce`, and
`705510dfe0f35d223a4bf6f5d2695ec5fd162341`.

The BGE profile uses
[`MoritzLaurer/bge-m3-zeroshot-v2.0-c`](https://huggingface.co/MoritzLaurer/bge-m3-zeroshot-v2.0-c)
at revision `705510dfe0f35d223a4bf6f5d2695ec5fd162341`. Its model card
describes the `-c` checkpoint as multilingual, commercial-friendly, MIT
licensed, and recommends it over the English checkpoints for multilingual
input. The current artifact is approximately 1.14 GB before runtime memory.

All profiles currently use English candidate descriptions and hypothesis
templates. Profile IDs, profile revisions, resolved model identity,
prompt/candidate configuration, batch size, both abstention thresholds, and an
optional verified local artifact digest
contribute to a SHA-256 configuration digest emitted with each prediction.

The multilingual profiles cover English, Italian, French, and Spanish.
“Covers” means the selected NLI checkpoint supports those languages and the
software path is wired; it is **not** an accuracy claim.

## Why not generic DistilBERT or DeBERTa?

A generic base checkpoint is trained for language representation, not directly
for zero-shot classification. It needs a suitable NLI/classification head or
project-specific fine-tuning. Choosing a named NLI checkpoint makes the intended
task and provenance explicit.

## Smaller CPU profile

`multilingual-minilm-v1` is a six-layer XLM-RoBERTa NLI checkpoint with a
384-wide hidden representation and a 427,997,022-byte `safetensors` file. Its
model card reports an MIT license and cross-lingual transfer across more than
100 languages. Italian is not an explicit XNLI training language, so the
project treats Italian support as an empirical question. The four-language
development result is recorded separately and does not qualify the model as an
interactive default.

## Artifact policy

- No model, tokenizer, cache, or downloaded metadata is committed.
- The default revision is a complete immutable commit hash.
- Prompt and candidate behavior is selected by a versioned profile and
  represented by a deterministic configuration digest.
- Local loading is the default; network download requires
  `--allow-download`.
- Remote model code is disabled and `safetensors` is required.
- A local directory requires `--model-source`, `--model-id`,
  `--model-revision`, and `--model-manifest`. ID and revision must match the
  selected registered profile, and every relevant file must match the strict
  SHA-256 manifest before the adapter imports Transformers.
- The manifest is kept outside the model directory. Root `.cache` and `.git`
  directories are operational metadata and are excluded; every other file is
  inventoried. Symbolic links, hard links, special files, unsafe paths, added
  files, missing files, byte-budget races, and content changes fail closed.
- At load time the inventoried files are copied into a private `0700`
  temporary directory and that copy is verified against the manifest.
  Transformers reads the verified copy, which is removed after model and
  tokenizer construction. Cold loading therefore needs temporary free disk
  space approximately equal to the artifact size.
- A generated manifest binds bytes to a declared profile but is not signed
  provenance. Generate it only from a trusted copy of the pinned revision.
- Offline deployment should set `HF_HUB_OFFLINE=1` and
  `TRANSFORMERS_OFFLINE=1`.

The Transformers documentation describes
[offline mode and local files](https://huggingface.co/docs/transformers/en/installation#offline-mode).

On a compatible CPU-only Linux host, install the CPU PyTorch build before the
project extra to avoid resolving unused accelerator packages:

```console
python -m pip install --index-url https://download.pytorch.org/whl/cpu \
  'torch>=2.4,<3'
python -m pip install '.[ml]'
```

Use the [official PyTorch installer](https://pytorch.org/get-started/locally/)
to confirm the correct command for other platforms.

## Selecting a profile

List the registered profiles without importing Transformers or loading an
artifact:

```console
log-classify models
```

The machine-readable catalog reports `rules` first as the safe default. Its
`execution_tier` values are intended operating roles rather than performance
guarantees; every zero-shot item remains `quality_status: unqualified`.

Known profiles can be resolved from the Hub only with explicit permission:

```console
log-classify evaluate tests/fixtures/synthetic-evaluation-multilingual.jsonl \
  --adapter zero-shot --model-profile multilingual-minilm-v1 --allow-download
```

For offline use, pass a local directory plus the exact identity and revision of
the selected profile and its verified external manifest:

```console
log-classify model-manifest create /models/english-deberta \
  --model-profile english-deberta-v1 > /models/english-deberta.manifest.json
log-classify model-manifest verify /models/english-deberta \
  /models/english-deberta.manifest.json \
  --model-profile english-deberta-v1
log-classify classify input.jsonl output.jsonl --adapter zero-shot \
  --model-profile english-deberta-v1 \
  --model-source /models/english-deberta \
  --model-id MoritzLaurer/deberta-v3-base-zeroshot-v2.0-c \
  --model-revision bddf8c5411c34ac3565e16e04384fd68b2618dda \
  --model-manifest /models/english-deberta.manifest.json
```

`--subsystem-threshold` and `--severity-threshold` can
override the shared `--confidence-threshold`; resolved values enter the
configuration digest.

The authenticated web selector can expose profiles lazily:

```console
log-classify web ./state/workspace.sqlite3 \
  --enable-model-profile english-deberta-v1 \
  --enable-model-profile multilingual-minilm-v1 \
  --enable-model-profile multilingual-mdeberta-v1 \
  --enable-model-profile multilingual-bge-m3-v1
```

Downloads remain disabled unless `--allow-download` is also supplied.

## Known risks

- The fast MiniLM profile is capacity-suitable on the measured CPU but produced
  weak development-set severity accuracy. mDeBERTa and BGE-M3 loaded on CPU,
  but their full 40-record runs were interrupted without metrics.
- NLI cost grows with records multiplied by candidate labels.
- Scores depend on candidate wording and the hypothesis template.
- Scores are not calibrated probabilities and do not create a true unknown
  class; the adapter therefore exposes an explicit abstention threshold.
- Technical logs may differ strongly from the model's training domain.
- Input minimization remains the caller's responsibility.
- A 40-row synthetic development fixture can detect wiring regressions but is
  too small and too close to the public taxonomy to authorize deployment.
