# Cloud development testing

GitHub Codespaces provides an isolated, disposable environment for reviewing
the source, running the CLI, and executing the automated test suite without a
local Python setup.

> [!IMPORTANT]
> This is a development environment, not a hosted service. The authenticated
> web workspace remains localhost-only and must not be exposed through a public
> forwarded port. Use only the synthetic fixtures included in the repository.

## Start a Codespace

Open the repository in Codespaces:

[Create a Codespace](https://codespaces.new/rikimela1992/log-classification-pipeline?quickstart=1)

Keep the default 2-core machine. Container creation installs the package, web
test dependencies, and quality tools in `.venv`, then runs the runtime doctor.
It does not install ML dependencies or download model weights.

## Run the smoke test

From the Codespace terminal:

```console
.venv/bin/log-classify doctor --require web
.venv/bin/log-classify validate examples/input-valid.jsonl
.venv/bin/log-classify classify \
  examples/input-valid.jsonl /tmp/classified.ndjson
sed -n '1,5p' /tmp/classified.ndjson
```

The default `rules` profile is deterministic and offline. The output in
`/tmp` disappears with the Codespace.

## Run the complete checks

```console
.venv/bin/python -W error -m unittest discover -s tests -v
.venv/bin/ruff check src tests examples packaging
.venv/bin/bandit -q -r src -ll
.venv/bin/coverage run -m unittest discover -s tests
.venv/bin/coverage report
.venv/bin/pip-audit --local --skip-editable --progress-spinner off
```

The test suite and examples contain invented records only. Do not upload real
logs, credentials, infrastructure identifiers, model artifacts, or datasets to
the Codespace.

## Test the browser workspace

The browser application deliberately binds to `127.0.0.1` and validates local
Host headers. Test it from a local checkout as documented in
[Web workspace](web-workspace.md). A cloud-hosted browser deployment is outside
the supported security boundary for this alpha.

Delete the Codespace when the review is complete to stop storage consumption.
