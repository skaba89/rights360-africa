# Module juridique et contentieux (PHASE 2)

> Module activable par institution (double gate `tenant_modules.legal` + `module_entitlements.legal`).
> **Avertissement de conformité** : cet outil est un enregistrement opérationnel des données
> juridiques. Il ne prend **aucune décision juridique automatisée** et ne doit **jamais** être
> présenté comme conforme à une juridiction sans validation par un professionnel du droit
> localement compétent.

## Périmètre (migration `0028_legal`)

Neuf tables, toutes isolées par RLS (`app.tenant_id`, rôle `rights360_runtime` `NOBYPASSRLS`) :

| Table | Rôle | RBAC |
|---|---|---|
| `legal_cases` | Dossiers juridiques (catégorie, statut, priorité, contrepartie) | `legal:read` / `legal:write` |
| `legal_case_parties` | Parties (ayants droit, exploitants, héritiers, mandataires, externes) | `legal:write` |
| `legal_case_events` | Historique immuable des décisions / procédures (amiables, judiciaires, mises en demeure, réclamations) | `legal:write` (append-only) |
| `legal_decisions` | Décisions sensibles (transitions de statut) — validation humaine par double revue | `legal:write` (proposer) / `legal:decide` (revue) |
| `legal_deadlines` | Calendrier des échéances + notification | `legal:read` / `legal:write` |
| `legal_mandates` | Mandats de représentation (territoire, période, révocation) | `legal:write` / `legal:decide` (révocation) |
| `legal_successions` | Successions et héritiers (parts en bps, approbation) | `legal:write` / `legal:decide` (approbation) |
| `legal_contracts` | Contrats et accords de réciprocité (territoire, validité) | `legal:write` |
| `legal_case_documents` | Lien dossiers ↔ GED existante (non invasif) | `legal:write` |

## RBAC ajouté (`permissions.py`)

- **admin** : `legal:read`, `legal:write`, `legal:decide`
- **manager** : `legal:read`, `legal:write` (peut proposer, ne peut pas décider)
- **auditor** : `legal:read`

## Validation humaine obligatoire des décisions sensibles

Les transitions de statut affectant les droits (`amicable`, `judicial`, `resolved`, `closed`,
`withdrawn`) **ne peuvent pas** être posées directement :

1. Un administrateur (`legal:write`) **propose** une décision (`POST /cases/{id}/decisions`) avec
   un statut cible et une justification. La proposition est `pending`.
2. Un **second administrateur indépendant** (`legal:decide`, ≠ proposant) **revue** la décision
   (`POST /decisions/{id}/review`). L'auto-revue est refusée (409), comme pour les reversements.
3. À l'approbation, la transition est appliquée (statut + `closed_on` si résolution/clôture) et un
   **événement immuable** est ajouté à l'historique (`legal_case_events`, kind `decision`). Une
   re-revue est idempotemment bloquée (409).

La révocation de mandat et l'approbation de succession nécessitent un approbateur `legal:decide`
(l'auto-approbation de succession est refusée, 409) ; un événement d'audit est journalisé pour
chaque action (`audit_events`, action `legal.*`).

## API (préfixe `/api/v1/legal`)

- `GET/POST /cases` · `GET /cases/{id}` · `PATCH /cases/{id}/status` (non-sensible uniquement)
- `POST /cases/{id}/parties` · `GET/POST /cases/{id}/events` · `GET/POST /cases/{id}/deadlines`
- `PATCH /deadlines/{id}` · `GET/POST /cases/{id}/documents`
- `POST /cases/{id}/decisions` · `GET /cases/{id}/decisions` · `POST /decisions/{id}/review`
- `GET/POST /mandates` · `POST /mandates/{id}/revoke`
- `GET/POST /successions` · `POST /successions/{id}/approve`
- `GET/POST /contracts`

Chaque route : `require_permission` → `tenant_transaction` → `require_enabled_module('legal')`.

## Tests

- `test_legal.py` (unitaire, no DB) : constantes `SENSITIVE_TRANSITIONS`, endpoints requièrent auth (401), validation payload (422).
- `legal_integration.py` (CI docker, gated) : deux admins MFA-enrolled → création dossier, proposition, **auto-revue bloquée (409)**, **transition directe sensibles rejetée (422)**, approbation indépendante applique la transition + enregistre l'événement, re-revue bloquée, révocation mandat, succession (auto-approbation bloquée puis approbation indépendante), contrat.

## Conformité aux règles

- Aucune décision juridique automatisée ; validation humaine obligatoire sur les décisions sensibles.
- Isolation tenant RLS (RLS + FORCE RLS + policy `tenant_scope`).
- Journalisation immuable (`legal_case_events` append-only + `audit_events`).
- Aucune donnée réelle ; aucune intégration externe ; aucun paiement ; pas présenté comme conforme sans validation locale compétente.
