# Bootstrap administrateur local (PHASE 1)

## Problème

Un `docker compose up` laisse une stack saine mais **vide** : aucune
organisation, aucun compte. `bootstrap_account.py` existe mais est interactif
(`getpass`), non documenté et non câblé dans Compose. L'administrateur ne peut
donc pas se connecter localement — c'est la cause racine du « problème de
connexion administrateur local ».

## Solution (non destructive)

`app/bootstrap_seed.py` crée la première organisation + administrateur depuis
des variables d'environnement, de façon reproductible et idempotente. Il
complète `bootstrap_account.py` (interactif) sans le supprimer.

### Procédure DEV

```bash
# 1. Générer une clé MFA Fernet (une seule fois, conserver dans .env)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 2. .env (DEV)
POSTGRES_PASSWORD=<≥ 24 car.>
RUNTIME_DB_PASSWORD=<distinct, ≥ 24 car.>
MFA_ENCRYPTION_KEY=<clé générée>

# 3. Démarrer la stack
docker compose up -d --wait

# 4. Créer le premier administrateur
RIGHTS360_DEV_BOOTSTRAP=1 \
bash ops/admin-bootstrap.sh admin@dsig-dev.invalid dsig-dev "DSIG Dev"
# => affiche organization_id, account_id, email et un mot de passe généré
#    (ou RIGHTS360_BOOTSTRAP_PASSWORD pour en fournir un ≥ 12 car.)

# 5. Ouvrir le portail et enrôler MFA
#    http://127.0.0.1:8500/portal
#    - email + mot de passe généré -> le portail force la vue MFA
#    - setup (mot de passe) -> secret TOTP
#    - confirmer avec un code TOTP -> codes de récupération
#    - terminer -> se reconnecter avec un code TOTP

# 6. (Optionnel) Accès console plateforme DSIG — uniquement APRÈS MFA activée
docker compose run --rm --no-deps -T -v "${PWD}/backend:/workspace:ro" -w /workspace migrate \
  sh -c 'PYTHONPATH=/workspace python -m app.bootstrap_platform_admin grant \
         --account-id <account_id> --organization-id <organization_id>'
```

## Garde-fous

- `RIGHTS360_DEV_BOOTSTRAP=1` obligatoire (refuse sinon).
- Idempotent : `ON CONFLICT (slug) DO NOTHING` ; échoue si le slug ou l'email
  existe déjà (jamais d'altération d'une organisation/compte existant).
- N'accorde **pas** l'accès plateforme (la CLI `bootstrap_platform_admin`
  exige MFA activée par conception).
- N'effectue aucun paiement réel ni déploiement.

## CI

Le parcours admin (enrôlement MFA via le portail) est couvert par
`backend/tests/admin_browser.cjs` + `backend/tests/seed_admin_e2e.py` (gated
`RIGHTS360_DISPOSABLE_E2E=1` + `POSTGRES_PASSWORD=ci-ephemeral-only`), ajouté
au job `docker` de la CI.
