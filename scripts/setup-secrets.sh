#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════
#  setup-secrets.sh — Génère tous les secrets Docker au premier déploiement.
#
#  Usage :
#      ./scripts/setup-secrets.sh
#
#  Idempotent : ne réécrit pas un secret déjà présent.
# ════════════════════════════════════════════════════════════
set -euo pipefail

SECRETS_DIR="$(dirname "$0")/../secrets"
mkdir -p "$SECRETS_DIR"
cd "$SECRETS_DIR"

write_if_missing() {
    local name="$1" value="$2"
    if [[ -f "${name}.txt" ]]; then
        echo "  [skip] ${name}.txt existe déjà"
        return
    fi
    printf "%s" "$value" > "${name}.txt"
    chmod 600 "${name}.txt"
    echo "  [new ] ${name}.txt généré"
}

gen_random() {
    openssl rand -base64 48 | tr -d '\n' | tr -d '=' | tr '/+' '_-'
}

echo "── Génération des secrets MailGuardianX ──"

# ── Secrets aléatoires ──
write_if_missing "secret_key"            "$(gen_random)"
write_if_missing "api_key_pepper"        "$(gen_random)"
write_if_missing "postgres_password"     "$(gen_random)"
write_if_missing "mysql_root_password"   "$(gen_random)"
write_if_missing "mysql_misp_password"   "$(gen_random)"
write_if_missing "redis_password"        "$(gen_random)"
write_if_missing "grafana_password"      "$(openssl rand -base64 24 | tr -d '\n')"
write_if_missing "misp_admin_passphrase" "$(gen_random)"

# ── Valeurs fixes ──
write_if_missing "postgres_user"      "postgres"
write_if_missing "misp_admin_email"   "admin@mailguardianx.local"

# ── URLs composées (lisent les passwords déjà générés ci-dessus) ──
#
#  IMPORTANT: on utilise le superuser "postgres" dont on connaît le mot de passe
#  (POSTGRES_PASSWORD_FILE dans le container postgres = postgres_password.txt).
#  Pas besoin de créer un user séparé — évite les problèmes de password mismatch.
#
PG_PASS="$(cat postgres_password.txt)"
REDIS_PASS="$(cat redis_password.txt)"

write_if_missing "database_url" \
    "postgresql+asyncpg://postgres:${PG_PASS}@postgres:5432/orchestrator_db"
write_if_missing "cape_db_url" \
    "postgresql://postgres:${PG_PASS}@postgres:5432/cape_db"

# Redis — URL complète avec mot de passe.
# Ces secrets sont montés dans les containers (pas d'env var sur le host).
write_if_missing "redis_url"             "redis://:${REDIS_PASS}@redis:6379/0"
write_if_missing "celery_broker_url"     "redis://:${REDIS_PASS}@redis:6379/1"
write_if_missing "celery_result_backend" "redis://:${REDIS_PASS}@redis:6379/2"

# ── Placeholders à remplir manuellement ──
write_if_missing "azure_tenant_id"      "FILL_WITH_AZURE_TENANT_ID"
write_if_missing "azure_client_id"      "FILL_WITH_AZURE_CLIENT_ID"
write_if_missing "azure_client_secret"  "FILL_WITH_AZURE_CLIENT_SECRET"
write_if_missing "cape_api_token"       "GENERATED_AT_FIRST_RUN"
write_if_missing "misp_api_key"         "GENERATED_AT_FIRST_RUN"

# ── Lecture par Grafana (uid 472 dans son image officielle) ──
#
#  Docker Compose hors mode Swarm ne chiffre pas les secrets : ce sont de
#  simples bind mounts, qui conservent les permissions du fichier hôte
#  (chmod 600, propriété de l'utilisateur qui a lancé ce script). Le
#  process Grafana tourne sous un autre utilisateur (uid 472) et n'a ni la
#  propriété ni les droits root pour lire postgres_password.txt ou
#  grafana_password.txt — il bouclerait sinon en redémarrage avec une
#  erreur "permission denied" sur ces deux fichiers.
#
#  Une ACL (`setfacl`) accorde une lecture ciblée à cet uid précis sans
#  élargir les permissions standard (chmod 600 reste en place pour tout
#  le monde d'autre).
GRAFANA_UID=472
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m "u:${GRAFANA_UID}:r" postgres_password.txt grafana_password.txt
    echo "  [acl ] lecture accordée à l'uid ${GRAFANA_UID} (Grafana) sur postgres_password.txt et grafana_password.txt"
else
    echo "  [warn] setfacl introuvable (paquet 'acl' non installé) — Grafana risque de"
    echo "         ne pas pouvoir lire ses secrets. Installer puis relancer ce script :"
    echo "           sudo apt install -y acl && ./scripts/setup-secrets.sh"
fi

echo
echo "✅ Secrets prêts dans $SECRETS_DIR"
echo
echo "Étapes restantes :"
echo "  1. Remplir azure_tenant_id.txt / azure_client_id.txt / azure_client_secret.txt"
echo "  2. Copier les variables non-secrètes : cp .env.example .env  (puis nano .env)"
echo "  3. Démarrer la stack :"
echo "       - un seul serveur  : docker compose --profile sandbox up -d"
echo "       - deux machines    : docker compose up -d  (puis voir GUIDE-DEPLOIEMENT.md, Topologie B)"
echo "  4. Appliquer les migrations : docker compose exec orchestrator alembic upgrade head"
echo "  5. Récupérer le CAPE API token après boot CAPE → mettre à jour cape_api_token.txt"
echo "  6. Récupérer la MISP API key depuis l'UI MISP → misp_api_key.txt"
echo "  7. Restart orchestrator : docker compose restart orchestrator celery-worker"
