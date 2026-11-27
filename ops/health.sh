#!/usr/bin/env bash
set -euo pipefail
env_name="${1:?Usage: bash ops/health.sh rec|prod}"
case "$env_name" in rec) port=8501;; prod) port=8502;; *) exit 2;; esac
for endpoint in healthz readyz; do
  curl --fail --silent --show-error --max-time 10 "http://127.0.0.1:$port/$endpoint"
  printf '\n'
done
