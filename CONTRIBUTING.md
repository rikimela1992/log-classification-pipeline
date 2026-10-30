# Contributing

This alpha accepts small, reviewable changes backed by synthetic data. Do not
submit real logs, credentials, private infrastructure identifiers, datasets,
model weights, or operational configuration.

## Development checks

Use Python 3.12 or newer in an isolated environment:

```console
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[web,test,quality]'
.venv/bin/ruff check src tests examples packaging
.venv/bin/bandit -q -r src -ll
.venv/bin/coverage run -m unittest discover -s tests
.venv/bin/coverage report
.venv/bin/pip-audit --local --skip-editable --progress-spinner off
```

The optional Gradio `ui` and `demo` extras are excluded from this audit: Gradio
currently caps Pillow below the releases that fix its published advisories. They
are not part of the Linux packages or the web workspace; use them only with
trusted local input until that cap is lifted.

Keep changes fail-closed: malformed input, invalid predictor output, interrupted
work, or an unsafe artifact must never produce a partial successful result.

Report vulnerabilities through GitHub private vulnerability reporting rather
than a public issue. Follow `SECURITY.md` for the required synthetic reproducer.
