# Phase 4 — Finance et comptabilité SYSCOHADA

## Objectif

Porter le score Finance de **55 à ~80/100** (cible roadmap : 82) en ajoutant la
couche SYSCOHADA configurable qui manquait au moteur comptable existant
(`accounting_entries`/`accounting_lines`, migration 0021). Aujourd'hui,
`accounting_lines.account_key` est une chaîne libre et `accounting.py` code en
dur cinq comptes génériques (`receivable`, `royalties_unallocated`,
`cash_unverified`, `management_commission`, `beneficiary_payable`). La phase 4
garde ce moteur double-entrée intact et ajoute, par-dessus, un plan comptable
configurable, des journaux, des exercices/périodes avec clôture multi-niveaux,
des contrepassations, des retenues à la source et des états de synthèse
(balance générale, grand livre, relevé ayant droit).

## Schéma (migration 0030, down_revision 0029)

Sept nouvelles tables, toutes `organization_id`-scopées avec RLS
(`tenant_scope` sur `app.tenant_id`), `UniqueConstraint(organization_id, id)`
et `UniqueConstraint(organization_id, <business key>)` :

| Table | Rôle | Contraintes notables |
|---|---|---|
| `chart_of_accounts` | Plan comptable configurable (classes SYSCOHADA 1-8) | `syscohada_class IN (1..8)`, `account_type IN (asset,liability,equity,revenue,expense)`, `account_code ~ '^[0-9]{1,8}$'` |
| `account_mappings` | Pont generic_key → account_code SYSCOHADA | `generic_key IN (les 5 clés génériques)`, FK vers `chart_of_accounts` |
| `journals` | Journaux (ventes/encaissements/opérations/reversements) | `kind IN (sales,receipts,general,payouts)`, `code ~ '^[A-Z0-9]{1,10}$'` |
| `fiscal_periods` | Exercices + périodes (0 = annuel, 1-12 = mensuel) | `status IN (open,closed,locked)`, `period_index 0..12`, `ends_on >= starts_on` |
| `fiscal_period_reviews` | Approbations multi-niveaux avant clôture | `decision IN (approve,reject)`, `(org,period,reviewer)` unique (pas de double vote) |
| `accounting_reversals` | Contrepassations (écriture miroir équilibrée) | `(org, original_entry_id)` unique (une reversal par écriture), `original <> reversal` |
| `tax_rules` | Retenues à la source (par catégorie/pays) | `rate_bps 0..10000`, `country ~ '^[A-Z]{2}$'`, FK optionnelle vers chart |

`accounting_entries` est étendue non destructivement : `+journal_id`,
`+fiscal_period_id` (nullables, FK) et le `CHECK entry_source_valid`接纳
`'reversal'` comme nouveau `source_type` (une reversal = une vraie écriture
équilibrée qui annule l'original dans la balance ; `entry_source_unique`
garantit une seule reversal par écriture).

## Intégrité (triggers déferrés)

- `check_fiscal_period_close` (BEFORE UPDATE OF status sur `fiscal_periods`) :
  le passage à `'closed'` exige **≥ 2 approbations distinctes** et **aucun
  rejet**. Sinon `check_violation` → 409.
- `check_fiscal_period_review` (BEFORE INSERT sur `fiscal_period_reviews`) :
  pas de review sur période close/verrouillée, pas de 3ᵉ approbation au-delà
  de 2.

Ces triggers sont l'arrière-garde : le routeur valide aussi en amont, mais la
base reste cohérente même en accès SQL direct.

## RBAC

Quatre nouvelles permissions (`backend/app/permissions.py`) :

| Permission | admin | manager | auditor | artist |
|---|---|---|---|---|
| `finance:read` | ✓ | ✓ | ✓ | — |
| `finance:write` | ✓ | ✓ | — | — |
| `finance:close` | ✓ | ✓ | — | — |
| `finance:reconcile` | ✓ | ✓ | ✓ | — |

La clôture multi-niveaux exige 2 approbations distinctes : un admin + un
manager (les deux rôles ont `finance:close`). L'auditeur peut rapprocher
(`finance:reconcile`) et lire, mais pas clôturer seul.

## Routeur `finance.py` (`/api/v1/finance`)

Chart of accounts (`GET/POST /chart-of-accounts`, `POST /chart-of-accounts/seed`
idempotent), mappings (`GET/POST /account-mappings`), journaux (`GET/POST
/journals`), exercices (`GET/POST /fiscal-periods`), approbations et clôture
(`POST /fiscal-periods/{id}/reviews`, `POST /fiscal-periods/{id}/close`), états
(`GET /trial-balance` = balance générale SYSCOHADA-mappée, `GET /general-ledger`
= grand livre), contrepassation (`POST /accounting/entries/{id}/reverse`),
retenues (`GET/POST /tax-rules`) et relevé ayant droit
(`GET /beneficiaries/{artist_id}/statement`). Tout endpoint passe par
`require_enabled_module(conn, "finance")` (la clé `'finance'` existe déjà dans
`module_entitlements` depuis la migration 0012).

## Plan OHADA par défaut

`POST /chart-of-accounts/seed` insère un plan OHADA par défaut pour une société
de gestion collective de droits (7 comptes couvrant les classes 1, 4, 5, 6, 7)
et les 5 mappings génériques. Idempotent (`ON CONFLICT DO NOTHING`).

| generic_key | account_code | compte |
|---|---|---|
| receivable | 411000 | Clients |
| royalties_unallocated | 471000 | Compte d'attente (fonds non répartis) |
| cash_unverified | 521000 | Banque |
| management_commission | 706000 | Prestations de services |
| beneficiary_payable | 422000 | Ayants droit à payer |

## ⚠️ Validation professionnelle requise

Conformément à `ROADMAP_99.md` (« Règles SYSCOHADA qualifiées par un
professionnel compétent »), le plan comptable par défaut, les mappings et les
taux de retenue à la source sont des **valeurs de démarrage** pour une société
de gestion collective de droits. Avant toute mise en production, ils doivent
être **validés par un commissaire aux comptes** familiarisé avec le référentiel
SYSCOHADA applicable à la juridiction de l'organisation. En particulier : le
classement des comptes (notamment le 422 « ayants droit à payer » vs 467
« autres créanciers »), les taux de retenue à la source par pays/catégorie, et
les règles de clôture d'exercice.

## Tests

- `test_finance.py` (unitaire, job `api`) : validation Pydantic, cohérence du
  plan par défaut, 401 sur les routes de lecture.
- `finance_integration.py` (intégration, job `docker`) : seed chart+mappings,
  balance générale mappée, contrepassation qui annule, clôture multi-niveaux
  (0/1/2 approbations, 3ᵉ bloquée, review post-clôture bloquée), retenues,
  relevé ayant droit, isolation tenant (cleanup complet).

## Non livré dans cette phase (Phase 5+)

Rapprochements bancaires automatisés, simulation avant liquidation, exports
statutaires (liasse fiscale SYSCOHADA), connecteurs de paiement (Orange/MTN/
virement — Phase 5). Le moteur de paiement existant reste `execution_enabled=
False` par conception.
