#!/usr/bin/env bash
set -euo pipefail
unset SOURCE_TOKEN GITEA_TOKEN GITHUB_TOKEN
python .gitea/scripts/verify-source.py
