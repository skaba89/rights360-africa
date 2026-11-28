# Phase 5 — Banques et Mobile Money

## Objectif

Porter le score « Banque / Mobile Money » de **10 à ~35/100** (cible roadmap)
en ajoutant la couche d'exécution des paiements que le flux existant manquait.
Aujourd'hui `payouts.py` ne fait qu'*approuver* les payouts (double review →
`approved_for_review_only`) et code en dur `execution_enabled=False` sur chaque
réponse : aucun argent ne circule. La phase 5 ajoute une architecture de
connecteurs indépendante des fournisseurs (Orange Money / MTN MoMo / virement),
l'idempotence, la vérification des bénéficiaires, l'ingestion de webhooks
authentifiés (HMAC), le rapprochement, et rend le verrou `execution_enabled`
réel (platform setting DSIG-gated, `false` par défaut).

## DSIG GATE (verrou d'autorisation externe)

Per `ROADMAP_99.md` (ligne 119), les paiements comportent un **verrou
d'autorisation externe qui ne peut être levé que par le responsable DSIG**.
La migration 0031 crée la table `platform_settings` + la fonction
`public.payments_execution_enabled()` (SECURITY DEFINER) et sème
`payments_execution_enabled = 'false'`. Tant que ce drapeau est `false` :

- `payouts.py` renvoie `execution_enabled=false` (au lieu du hardcoded `False`),
- `POST /api/v1/payments/payouts/{id}/execute` s'exécute en **SANDBOX** :
  il enregistre une tentative `succeeded` avec `external_ref=sandbox-…` mais
  ne déplace aucun argent réel.

Basculer le drapeau à `'true'` (mode `live`) est un **processus humain DSIG**,
pas un changement de code : il faut insérer/mettre à jour la ligne
`platform_settings` via le canal platform-admin après autorisation DSIG. Les
connecteurs réels (appels API Orange/MTN/banque) ne sont PAS implémentés dans
cette phase — seule l'architecture + le hook le sont.

## Schéma (migration 0031, down_revision 0030)

Cinq nouvelles tables org-scopées (RLS `tenant_scope`) + une table platform :

| Table | Rôle | Contraintes notables |
|---|---|---|
| `payment_providers` | Config connecteur (org + provider) | `provider IN (orange_money,mtn_momo,bank_transfer)`, `mode IN (sandbox,live)`, unique(org, provider) |
| `payment_beneficiaries` | Coordonnées bénéficiaire (artist × channel) | `msisdn OR iban OR account_number` NOT NULL, unique(org, artist, channel) |
| `payment_attempts` | Tentatives d'exécution idempotentes | unique(org, idempotency_key) + unique(org, payout_id) — une tentative par payout |
| `payment_webhooks` | Callbacks providers (HMAC) | unique(org, provider, event_ref) — déduplication |
| `payment_reconciliations` | Rapprochement webhook ↔ attempt | unique(org, attempt_id) — un rapprochement par tentative |
| `platform_settings` | Drapeaux globaux DSIG (hors-org) | PK `key`, `payments_execution_enabled` semé à `false` |

`payout_orders` (0022) est étendu non destructivement : `+provider`,
`+beneficiary_id` (FK), `+external_ref`, `+executed_at` (nullables). Le flux
double-approbation existant (`payout_reviews` + trigger `check_payout_review`)
est inchangé.

## Routeur `payments.py` (`/api/v1/payments`)

- `GET/POST /providers` (payments:read/write) — config connecteurs.
- `GET/POST /beneficiaries` + `POST /beneficiaries/{id}/verify` (payments:read/write) — coordonnées + vérification.
- `POST /payouts/{order_id}/execute` (payments:execute) — exécute un payout **approuvé** (≥2 reviews) vers un bénéficiaire **vérifié** via un provider **configuré** ; idempotent (une tentative par payout) ; sandbox sauf DSIG.
- `GET /attempts` (payments:read).
- `POST /webhooks/{provider}?org=…` (PAS de Bearer — HMAC) — ingère un callback signé, le matche à une tentative par `external_ref`, déduplique par `event_ref`.
- `GET /reconciliations` + `POST /reconcile` (payments:read/reconcile) — rapproche un webhook à une tentative (non répétable).
- `GET /execution-status` (payments:read) — état du verrou DSIG.

## RBAC

Quatre nouvelles permissions (`permissions.py`) :

| Permission | admin | manager | auditor | artist |
|---|---|---|---|---|
| `payments:read` | ✓ | ✓ | ✓ | — |
| `payments:write` | ✓ | ✓ | — | — |
| `payments:execute` | ✓ | ✓ | — | — |
| `payments:reconcile` | ✓ | ✓ | ✓ | — |

`payouts.py` est patché pour renvoyer le **vrai** `execution_enabled` (appel à
`payments_execution_enabled()`) au lieu du `False` codé en dur.

## Idempotence + double approbation

- **Double approbation** : réutilise le flux `payout_reviews` existant (0022,
  trigger `check_payout_review`). `execute` n'accepte que les payouts
  `approved_for_review_only` (≥2 approbations distinctes, 0 rejet).
- **Idempotence** : `unique(org, payout_id)` garantit une seule tentative par
  payout ; re-exécuter renvoie la tentative existante. `unique(org,
  idempotency_key)` protège aussi contre les rejeux client.

## Webhooks HMAC

L'endpoint `POST /webhooks/{provider}?org=…` est **public** (pas de Bearer) :
il vérifie `X-Signature = hex HMAC-SHA256(body, provider.webhook_secret)` via
`hmac.compare_digest` (constant-time). Le `webhook_secret` est stocké par
provider config ; en production il viendrait d'un secrets manager (ici
sandbox). Le webhook matche la tentative par `external_ref` (renvoyé par le
provider) + déduplique par `(org, provider, event_ref)`.

## ⚠️ Limites + validation externe requise

- **Pas de connecteurs réels** : seuls Orange/MTN/virement sont modélisés en
  sandbox. Les appels API fournisseurs réels (auth, transfert, statut) sont un
  travail séparé post-DSIG.
- **DSIG gate obligatoire** : aucune exécution `live` ne peut se faire tant que
  `payments_execution_enabled` est `false`. Le levé est un processus humain DSIG.
- **Secrets** : `webhook_secret` + `credentials_ref` sont stockés en clair
  (sandbox) ; la production doit utiliser un secrets manager (Vault/KMS).
- **Conformité** : les connecteurs de paiement réels exigent une agrégation
  réglementaire (BCAO/CEMAC) + un PCI-DSS si carte — hors périmètre de cette
  phase.

## Tests

- `test_payments.py` (unitaire, job `api`) : validation Pydantic, format clé
  d'idempotence, machine à états du payout, 401 sur les routes.
- `payments_integration.py` (intégration, job `docker`) : chaîne complète
  (11 tables) + execute sandbox idempotent, webhook HMAC + matching + dédup,
  rapprochement non répétable, verrou DSIG sandbox, isolation tenant.

## Non livré (Phase 6+)

Paiements de masse (bulk), import de relevés bancaires, échecs/remboursements
automatiques, connecteurs réels Orange/MTN/banque, webhooks sortants,
réconciliation automatisée.
