#!/usr/bin/env bash
# System-level backup wrapper (calls backup.py)
set -euo pipefail
cd "$(dirname "$0")"
python3 backup.py
