#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv
.venv/bin/python -m pip install 'pip==26.2.1'
.venv/bin/python -m pip install -e '.[web,test,quality]'
.venv/bin/log-classify doctor --require web
