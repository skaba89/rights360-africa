#!/usr/bin/env bash
set -euo pipefail
umask 077
archive="${1:?Usage: bash ops/verify-restore.sh /absolute/archive.dump}"
[[ "$archive" = /* && -f "$archive" && -f "$archive.sha256" ]] || exit 2
# Check only the supplied file; do not trust paths embedded in checksum manifests.
expected="$(cut -d ' ' -f1 "$archive.sha256")"
actual="$(sha256sum "$archive" | cut -d ' ' -f1)"
[[ "$expected" =~ ^[a-f0-9]{64}$ && "$expected" = "$actual" ]] || { echo "Checksum mismatch" >&2; exit 1; }
name="rights360-restore-$(openssl rand -hex 8)"
password="$(openssl rand -hex 32)"
runtime_password="$(openssl rand -hex 32)"
cleanup(){ docker rm -fv "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
# A fresh disposable database, no published ports and no external network.
docker run -d --name "$name" --network none -e POSTGRES_USER=rights360 -e POSTGRES_DB=rights360 -e POSTGRES_PASSWORD="$password" postgres:16 >/dev/null
for i in $(seq 1 60); do
  if docker exec "$name" pg_isready -U rights360 -d rights360 >/dev/null 2>&1 && docker exec "$name" test -s /var/lib/postgresql/data/PG_VERSION; then
    # Avoid racing temporary init server: require final postgres PID 1.
    if docker exec "$name" sh -c 'test "$(cat /proc/1/comm)" = postgres'; then break; fi
  fi
  sleep 2
done
docker exec "$name" pg_isready -U rights360 -d rights360
docker exec -i "$name" psql -U rights360 -d rights360 -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE rights360_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$runtime_password';
SQL
docker exec -i "$name" pg_restore -U rights360 -d rights360 --exit-on-error --single-transaction < "$archive"
docker exec "$name" psql -U rights360 -d rights360 -v ON_ERROR_STOP=1 -c 'SELECT version_num FROM alembic_version; SELECT count(*) AS institutions FROM organizations; SELECT count(*) AS works FROM works;'
docker exec "$name" psql -U rights360 -d rights360 -v ON_ERROR_STOP=1 -c "SET ROLE rights360_runtime; SELECT count(*) FROM organizations HAVING count(*)=0;" | grep -q '(1 row)'
echo "Isolated restore PASS; disposable container removed on exit."
