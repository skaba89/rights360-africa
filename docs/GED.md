# Phase 6 — GED entreprise

## Objectif

Porter le score « GED » de **45 à ~82/100** (cible roadmap) en ajoutant les
capacités entreprise que le flux documents existant (0026 : `documents` +
`document_versions` bytea + SHA-256 + versionning + archive) manquait :
quarantaine + antivirus, quotas, rétention + gel litiges, journal consultations,
URLs temporaires, métadonnées + recherche, abstraction stockage objet +
chiffrement. **« Jamais de téléchargement en quarantaine. »**

Non destructeur : la colonne `document_versions.content` + son CC d'intégrité
restent intactes (dual-write quand le stockage objet est activé). Les nouvelles
colonnes sont nullables/defaulted. Les 3 flags comportementaux (quarantaine /
stockage objet / chiffrement) sont des platform settings semés à `false` → le
flux upload/download existant est inchangé tant qu'un flag n'est pas levé.

## Schéma (migration 0032, down_revision 0031)

Six nouvelles tables org-scopées (RLS `tenant_scope`) :

| Table | Rôle | Contraintes notables |
|---|---|---|
| `document_storage` | Config backend (local/s3/b2) | unique(org), `backend IN (...)` |
| `document_quotas` | Quota org (octets + nb docs) | PK org, `max_bytes>0 AND max_documents>0` |
| `document_retention_policies` | Catégorie → retain_days | unique(org, category) |
| `document_litigation_holds` | Gel litige (released_at nullable) | index unique partiel `(org, doc) WHERE released_at IS NULL` |
| `document_access_log` | Journal consultations | `action IN (view/download/presign/scan/archive/hold/release)` |
| `document_metadata` | Métadonnées clé-valeur | unique(org, doc, key) |

ALTER `document_versions` : `+object_key`, `+encryption_iv`, `+ocr_text`,
`+quarantine_status` (default `'clean'`, CC `IN (clean/quarantine/infected)`).
ALTER `documents` : `+retention_until`, `+litigation_hold` (default false).

Platform settings seeds : `documents_quarantine_enabled` /
`documents_object_storage_enabled` / `documents_encryption_enabled` = `false`.
Fonction générique `public.platform_setting_bool(key text)` (SECURITY DEFINER).

## Storage backend (`storage.py`)

Abstraction indépendante du fournisseur :
- **LocalStorageBackend** (sandbox/CI) : écrit les objets sous
  `RIGHTS360_STORAGE_DIR` (default `/tmp/rights360-storage`).
- Chiffrement AES (Fernet) quand `encryption_enabled` : l'objet est chiffré
  avant écriture (la colonne Postgres `content` reste en clair, dual-write).
- Presign tokens : HMAC-SHA256 signé `(org|doc|version|expiry)`, vérifiés en
  constant-time (`hmac.compare_digest`).

Migration contrôlée : `documents_object_storage_enabled=false` → contenu dans
Postgres (comportement existant). Levé à `true` → dual-write (Postgres + objet),
le download sert depuis l'objet si `object_key` est set.

## Routeur `ged.py` (`/api/v1/ged`)

- `GET/POST /storage` (documents:admin) — config backend.
- `GET/POST /quotas` (documents:admin) — quotas + usage (`used_bytes`/`used_documents`).
- `GET/POST /retention-policies` (documents:admin) — politiques de rétention.
- `POST /documents/{id}/litigation-hold` + `DELETE` (documents:admin) — gel / levée.
- `GET/POST /documents/{id}/metadata` (documents:read/write) — métadonnées.
- `GET /search?q=&category=` (documents:read) — recherche titre/métadonnées.
- `POST /documents/{id}/versions/{v}/presign` (documents:read) — URL temporaire.
- `POST /documents/{id}/versions/{v}/scan` (documents:admin) — verdict antivirus.
- `GET /documents/{id}/access-log` (documents:admin) — journal consultations.

## `documents.py` patché (hooks comportementaux)

- **`store()`** : enforce le quota (`document_quotas` ; pas de ligne → illimité),
  set `quarantine_status` (`quarantine` si flag on, sinon `clean`), dual-write
  objet si `documents_object_storage_enabled` (chiffré si `encryption_enabled`).
- **`download()`** : auth par Bearer OU token presign (`_identity_or_token`),
  **bloque le download si `quarantine_status='quarantine'`** (409), sert depuis
  l'objet si `object_key` set (déchiffré si besoin), vérifie SHA-256, log dans
  `document_access_log` (anonyme pour les downloads presign).

## RBAC

Nouvelle permission `documents:admin` (admin + manager) pour storage/quotas/
retention/litigation/scan/access-log. `documents:read`/`write`/`archive`
(existing) inchangés.

## ⚠️ Limites + validation externe

- **Pas de vrai antivirus** : `scan` enregistre le verdict (admin) après scan
  externe ; l'intégration ClamAV/YARA est post-déploiement.
- **Pas de vrai S3/B2** : seul le backend local est implémenté (sandbox). Les
  backends S3/B2 sont l'interface + config ; l'implémentation réelle (boto3)
  est un travail séparé.
- **OCR** : colonne `ocr_text` présente mais non peuplée (hook only).
- **Rétention automatique** : les politiques sont stockées mais le sweep
  automatique (delete expirés) n'est pas implémenté (Phase 9 data warehouse).
- **Stockage objet** : dual-write seulement (la bascule full-objet — drop de la
  colonne `content` — est une migration contrôlée post-validation).

## Tests

- `test_ged.py` (unitaire, job `api`) : validation Pydantic, presign/verify,
  chiffrement round-trip, 401 routes.
- `ged_integration.py` (intégration, job `docker`) : quarantine+scan, quotas
  (413/relax), litigation hold/release, metadata+search, presign download
  anonyme, access journal, isolation tenant.
