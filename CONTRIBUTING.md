# Contributing

This alpha accepts small, reviewable changes backed by synthetic data. Do not
submit real logs, credentials, private infrastructure identifiers, datasets,
model weights, or operational configuration.

## Development checks

Use Python 3.12 or newer in an isolated environment:

```console
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[web,ui,test,quality]'
.venv/bin/ruff check src tests examples packaging
.venv/bin/bandit -q -r src -ll
.venv/bin/coverage run -m unittest discover -s tests
.venv/bin/coverage report
.venv/bin/pip-audit --local --skip-editable --progress-spinner off
```

Keep changes fail-closed: malformed input, invalid predictor output, interrupted
work, or an unsafe artifact must never produce a partial successful result.

Report vulnerabilities through GitHub private vulnerability reporting rather
than a public issue. Follow `SECURITY.md` for the required synthetic reproducer.
