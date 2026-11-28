#!/usr/bin/env bash
# Reproducible local administrator bootstrap for DEV/REC.
# Creates the first organization + admin from environment variables so a fresh
# `docker compose up` no longer leaves an empty stack. Non-destructive and
# gated: refuses unless RIGHTS360_DEV_BOOTSTRAP=1.
#
# Usage:
#   MFA_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
#   POSTGRES_PASSWORD=... RUNTIME_DB_PASSWORD=$(openssl rand -hex 24) \
#   bash ops/admin-bootstrap.sh admin@example.invalid dsig-dev "DSIG Dev"
#
# After bootstrap, enroll MFA via http://127.0.0.1:8500/portal, then optionally
# grant platform access with: python -m app.bootstrap_platform_admin grant \
#   --account-id <id> --organization-id <id>   (requires MFA enabled).
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <email> <org-slug> [org-name]" >&2
  exit 64
fi
email="$1"; org_slug="$2"; org_name="${3:-$org_slug}"

if [[ "${RIGHTS360_DEV_BOOTSTRAP:-}" != "1" ]]; then
  echo "Refusing: set RIGHTS360_DEV_BOOTSTRAP=1 to seed a local administrator." >&2
  exit 1
fi

: "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD}"
: "${RUNTIME_DB_PASSWORD:?Set RUNTIME_DB_PASSWORD}"
: "${MFA_ENCRYPTION_KEY:?Set MFA_ENCRYPTION_KEY}"

export RIGHTS360_BOOTSTRAP_EMAIL="$email"
export RIGHTS360_BOOTSTRAP_ORG_SLUG="$org_slug"
export RIGHTS360_BOOTSTRAP_ORG_NAME="$org_name"

# Run inside the migrate container against the running DEV stack on port 8500.
docker compose run --rm --no-deps -T \
  -e RIGHTS360_DEV_BOOTSTRAP=1 \
  -e RIGHTS360_BOOTSTRAP_EMAIL="$email" \
  -e RIGHTS360_BOOTSTRAP_ORG_SLUG="$org_slug" \
  -e RIGHTS360_BOOTSTRAP_ORG_NAME="$org_name" \
  -v "${PWD}/backend:/workspace:ro" -w /workspace migrate \
  sh -c 'PYTHONPATH=/workspace python -m app.bootstrap_seed'
