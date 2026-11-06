#!/usr/bin/env sh
set -eu
python -m pip install -e ".[dev,mcp]"
python -m pytest -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python tests/deep_security_test.py
python -m compileall -q src
python -m build
python -m twine check dist/*
