# Rights360 deployment preparation

## Environment isolation
Linux / Docker Compose >= 2.24.4 required for !override. DEV uses loopback 8500. REC uses project rights360-rec, loopback 8501; PROD uses rights360-prod, loopback 8502. Project-specific default networks and named volumes separate databases. Verify ports and disk/RAM capacity on the target VPS before startup; these ports have not been checked on the actual host. No public listener is added. Do not use production data in REC.

Create a private directory outside the checkout (mode 700), and a separate env file (mode 600) per environment. Use distinct random 32-byte hex database passwords and a URL-safe base64-encoded 32-byte MFA key (including padding). Preserve existing secrets; changing the env file is not database password rotation. Back up MFA keys separately in an encrypted secret store: a database dump alone cannot restore MFA access.

Example REC startup after approval, from a clean reviewed checkout:
```bash
bash ops/preflight.sh rec "$HOME/.rights360/rec.env"
(
unset POSTGRES_PASSWORD RUNTIME_DB_PASSWORD MFA_ENCRYPTION_KEY COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_ENV_FILES
docker compose --env-file "$HOME/.rights360/rec.env" -p rights360-rec -f compose.yaml -f compose.rec.yaml up -d --build --wait --wait-timeout 180
)
bash ops/health.sh rec
```
Review migrate exit code and logs locally; never publish secrets. Do not run production deployment yet. Images are still built from the checked-out source and base images are not digest-pinned. Future release gates must enforce immutable images, explicit migration approval, backups and security review.

## Backup and recovery
```bash
bash ops/backup.sh rec "$HOME/.rights360/rec.env" "$HOME/rights360-backups/rec"
bash ops/verify-restore.sh /absolute/path/to/archive.dump
```
Backups contain sensitive personal and financial data, including authentication hashes and encrypted MFA material. Local files are permission-restricted but not encrypted. Do not upload to GitHub or attach to CI artifacts. Configure encrypted offsite storage, retention and restore drills before production. The restore test creates a random disposable container with no network or published port, recreates the runtime role, restores the archive and checks schema and default-deny RLS. It is not an end-to-end disaster recovery exercise. It does not restore external storage, secrets, application images or validate all application workflows.

## Release/rollback
Capture the exact Git SHA and image IDs, take a verified backup, stop writes during incompatible migration, migrate in REC first, run smoke and business acceptance checks. Never use docker compose down -v on a live environment. Rolling back an image alone is unsafe after incompatible schema changes. Restore into an isolated environment first, obtain explicit approval and preserve the current database before any recovery cutover. No automated destructive rollback is provided.

## HTTPS and supervision
Use the existing host reverse proxy only after verifying its configuration and available ports. If Caddy runs inside a container, loopback on the host is not reachable through that container's own loopback; design a dedicated scoped proxy network or host gateway route and validate exposure separately. No Caddy config or DNS records are changed here. REC access must be restricted. Add external TLS verification, alerting, resource limits, log retention, immutable release artifacts and secret rotation before production. The health script is a manual probe, not an installed monitoring service.
