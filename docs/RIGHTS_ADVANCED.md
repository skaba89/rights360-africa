# Droits d'auteur et voisins avancés (PHASE 3)

> Étend le schéma œuvres/artistes/droits **de façon non destructive** (migration `0029`). ISWC
> existe déjà sur `works` (migration `0015`). Les nouveaux identifiants sont validés au niveau
> format uniquement ; l'enregistrement officiel auprès des organismes compétents (ISWC/IPI/ISRC/ISNI)
> relève de l'institution.

## Périmètre (migration `0029_rights_advanced`)

### Extensions de tables existantes (colonnes nullables — lignes existantes préservées)
- **`artists`** : `category` (titulaire), `ipi` (`^[0-9]{9,11}$`), `isni` (`^[0-9]{15}[0-9X]$`) + unicités par tenant.
- **`works`** : `genre`, `language`, `derivation` (original/derived/adaptation/arrangement), `visibility` (public/private), `parent_work_id` (auto-référence org-scopée pour œuvres dérivées).

### Nouvelles tables (RLS `tenant_scope`, grant `rights360_runtime`)
| Table | Rôle |
|---|---|
| `recordings` | Enregistrements sonores liés à une œuvre, ISRC (`^[A-Z]{2}[0-9A-Z]{3}[0-9]{2}[0-9]{5}$`) unique par tenant |
| `rights_grants` | Droits territoriaux bornés dans le temps : rôle, territoire, `scope` (collective/direct), `basis_points`, validité, statut (active/terminated/disputed) |
| `distribution_rules` | Règles de répartition **par catégorie** (mechanical/performance/broadcast/synchronization/digital/public_lending/other), **versionnées** et reproductibles (`allocation` JSONB, somme 10000) |
| `rights_unidentified` | Montants en attente d'identification (lien optionnel à une distribution) |
| `rights_claims` | Réclamations/ajustements d'un titulaire, avec workflow d'approbation (pending/approved/rejected/paid) |

## RBAC (`permissions.py`)
- **admin** : `rights:read`, `rights:write`, `rights:decide`
- **manager** : `rights:read`, `rights:write`
- **auditor** : `rights:read`

## API (préfixe `/api/v1/rights`, gate `works`)
- `PATCH /holders/{artist_id}` — catégorie / IPI / ISNI
- `GET/POST /recordings` (ISRC)
- `GET/POST /grants` · `POST /grants/{id}/terminate`
- `GET/POST /rules` · `POST /rules/{id}/activate` (versionnement optimistic-lock `expected_version`, activation supersède la version active précédente de la catégorie)
- `GET/POST /unidentified` · `PATCH /unidentified/{id}`
- `GET/POST /claims` · `POST /claims/{id}/review` · `POST /claims/{id}/paid`

## Décisions sensibles (validation humaine)
- **Réclamation** : proposition (`rights:write`) → revue par un approbateur **indépendant** `rights:decide` (auto-revue refusée 409, verrou advisory 365). Le passage « payé » exige d'abord une approbation (`rights:decide`).
- **Règle de répartition** : versionnement avec `expected_version` (conflit 409 si périmé) ; l'activation supersède la version active précédente. Historique complet conservé (reproductibilité des calculs).

## Tests
- `test_rights_advanced.py` (unitaire no-DB) : auth requise (401), formats ISRC/IPI/ISNI rejetés (422), allocation≠10000 rejetée (422).
- `rights_integration.py` (CI docker, gated) : identifiants titulaire + ISRC + subvention territoriale + **règles versionnées** (v1→active, v2 supersède, conflit version périmée 409) + montant non identifié résolu + **réclamation** (auto-revue 409, approbation indépendante, passage payé, re-revue 409).

## Conformité
- Aucune décision juridique automatisée ; validation humaine sur les réclamations.
- RLS tenant préservée ; journalisation `audit_events` (`rights.*`).
- Identifiants validés format uniquement (non présentés comme enregistrés officiellement).
- Aucune donnée réelle ; aucun paiement réel ; pas de déploiement.
