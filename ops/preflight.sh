#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
env_name="${1:?Usage: bash ops/preflight.sh rec|prod /absolute/private/env-file}"
env_file="${2:?Provide private environment file}"
case "$env_name" in rec|prod) ;; *) echo "Unsupported environment" >&2; exit 2;; esac
[[ "$env_file" = /* && -f "$env_file" && ! -L "$env_file" ]] || { echo "Private absolute regular env file required" >&2; exit 2; }
[[ "$(stat -c '%a' "$env_file")" = 600 || "$(stat -c '%a' "$env_file")" = 400 ]] || { echo "Restrict env file permissions to 600 or 400" >&2; exit 2; }
[[ "$(realpath "$env_file")" != "$(pwd -P)"/* ]] || { echo "Store secrets outside the repository" >&2; exit 2; }
command -v docker >/dev/null
docker compose version
# Shell variables must not override the explicitly selected environment file.
unset POSTGRES_PASSWORD RUNTIME_DB_PASSWORD MFA_ENCRYPTION_KEY COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_ENV_FILES
docker compose --env-file "$env_file" -p "rights360-$env_name" -f compose.yaml -f "compose.$env_name.yaml" config --format json | python3 -c '
import json,sys,base64
c=json.load(sys.stdin)
s=c["services"]; m=s["migrate"]["environment"]; a=s["api"]["environment"]
p=m["POSTGRES_PASSWORD"]; r=m["RUNTIME_DB_PASSWORD"]; k=m["MFA_ENCRYPTION_KEY"]
assert len(p)>=32 and len(r)>=32 and p!=r, "Require distinct database secrets, >=32 characters"
assert len(base64.b64decode(k,altchars=b"-_",validate=True))==32 and len(k)==44, "Invalid MFA key"
assert a["RUNTIME_DB_PASSWORD"]==r and a["MFA_ENCRYPTION_KEY"]==k
assert "POSTGRES_PASSWORD" not in a
assert not s["db"].get("ports")
assert all(x.get("host_ip")=="127.0.0.1" for x in s["api"]["ports"])
assert len(s["api"]["ports"])==1
assert s["api"]["read_only"] is True
print("Configuration checks PASS (secrets not printed)")
'
echo "Preflight passed; no services started."
