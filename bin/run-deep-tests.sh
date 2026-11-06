#!/usr/bin/env sh
set -eu
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python tests/deep_security_test.py
