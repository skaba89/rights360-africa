#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
env_name="${1:?Usage: bash ops/backup.sh rec|prod /absolute/env-file /absolute/backup-dir}"
env_file="${2:?Environment file required}"
backup_dir="${3:?Backup directory required}"
bash ops/preflight.sh "$env_name" "$env_file"
[[ "$backup_dir" = /* ]] || exit 2
mkdir -p -m 700 "$backup_dir"
[[ "$(realpath "$backup_dir")" != "$(pwd -P)"/* && "$(stat -c '%a' "$backup_dir")" = 700 ]] || { echo "Backup directory must be private and outside repository" >&2; exit 2; }
unset POSTGRES_PASSWORD RUNTIME_DB_PASSWORD MFA_ENCRYPTION_KEY COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_ENV_FILES
compose=(docker compose --env-file "$env_file" -p "rights360-$env_name" -f compose.yaml -f "compose.$env_name.yaml")
tmp="$(mktemp "$backup_dir/.rights360-$env_name.XXXXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
"${compose[@]}" exec -T db pg_dump -U rights360 -d rights360 -Fc > "$tmp"
test -s "$tmp"
"${compose[@]}" exec -T db pg_restore -l < "$tmp" >/dev/null
name="rights360-$env_name-$(date -u +%Y%m%dT%H%M%SZ)-$(basename "$tmp" | sed 's/.*\.//').dump"
mv -- "$tmp" "$backup_dir/$name"
(cd "$backup_dir"; sha256sum "$name" > "$name.sha256")
printf 'Backup created: %s/%s\n' "$backup_dir" "$name"
