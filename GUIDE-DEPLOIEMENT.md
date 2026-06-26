# MailGuardianX — Guide de déploiement

Déployer la solution complète sur un serveur Ubuntu (recommandé : 64 Go RAM / 32 cœurs / 2 To).

---

## Pré-requis

- Ubuntu Server 22.04 ou 24.04 LTS
- Docker Engine ≥ 24.0
- Docker Compose v2 (`docker compose`)
- `openssl` (pour générer les secrets)
- Une application Azure AD (mode app-only) — voir section "Azure AD"

---

## 1. Cloner le dépôt

```bash
git clone https://github.com/f3n999/SandBox.git mailguardianx
cd mailguardianx
```

## 2. Générer les secrets

```bash
chmod +x scripts/setup-secrets.sh
./scripts/setup-secrets.sh
```

Ça crée `./secrets/*.txt` (gitignored). Édite ensuite :

```bash
nano secrets/azure_tenant_id.txt        # ID du tenant Azure
nano secrets/azure_client_id.txt        # Application (client) ID
nano secrets/azure_client_secret.txt    # Client secret (app-only)
```

## 3. Variables d'environnement non-secrètes

```bash
cp .env.example .env
nano .env
```

Active le scheduler une fois Azure configuré :

```bash
SCHEDULE_ENABLED=true
SCHEDULE_INTERVAL_MINUTES=15
```

## 4. Démarrer la stack

```bash
docker compose up -d
```

Premier démarrage : ~5-10 min (compilation YARA, init bases, signatures ClamAV).

Suivre les logs :

```bash
docker compose logs -f orchestrator
```

## 5. Migrations DB

Une fois Postgres prêt :

```bash
docker compose exec orchestrator alembic upgrade head
```

## 6. Récupérer les tokens MISP / CAPE

### CAPE API token

```bash
docker compose exec cape cat /opt/CAPEv2/conf/api.conf | grep token
```

Coller dans `secrets/cape_api_token.txt`.

### MISP API key

1. UI MISP : `https://<serveur>:8443`
2. Connexion avec l'email/passphrase admin (depuis `secrets/`)
3. Administration → List Auth Keys → Add authentication key
4. Coller la clé dans `secrets/misp_api_key.txt`

Restart :

```bash
docker compose restart orchestrator celery-worker
```

## 7. Créer la première clé API

```bash
curl -X POST http://localhost:8000/api/v1/admin/keys \
     -F "name=mgx-bootstrap" \
     -F "scopes=analyze,upload,admin"
```

**Réponse :** stocke le champ `key` (commence par `mgx_…`) — il ne sera plus jamais affiché.

## 8. Vérifier le pipeline

```bash
curl http://localhost:8000/health | jq
```

Tous les services doivent être `up` (sauf scheduler si Azure pas configuré).

## 9. Déclencher un premier scan Graph

```bash
curl -X POST http://localhost:8000/api/v1/scan/trigger \
     -H "X-API-Key: mgx_…"
```

---

## Azure AD — création de l'application

1. Portail Azure → **Microsoft Entra ID** → **App registrations** → **+ New registration**
2. Name : `MailGuardianX-Production`, Supported types : *Single tenant*
3. Copier **Application (client) ID** + **Directory (tenant) ID**
4. **Certificates & secrets** → **+ New client secret** → copier la valeur (≠ secret ID)
5. **API permissions** → **+ Add a permission** → **Microsoft Graph** → **Application permissions** :
   - `Mail.Read`
   - `User.Read.All`
6. **Grant admin consent** (bouton bleu) — obligatoire pour app-only

---

## Monitoring

- **Grafana** : http://serveur:3000 (admin / cat secrets/grafana_password.txt)
- **Prometheus** : http://serveur:9090
- **MISP** : https://serveur:8443

### Dashboards Grafana (provisionnés automatiquement)

| Dashboard | Source | Contenu |
|-----------|--------|---------|
| **SOC Verdicts (PostgreSQL)** | datasource `PostgreSQL-Verdicts` | **Vue démo** : emails analysés, bloqués, en quarantaine, répartition des verdicts, top menaces, top expéditeurs bloqués, courbe analysés/bloqués. Lit directement `email_analyses` / `attachment_verdicts`. |
| **SOC Overview** | datasource `Prometheus` | Santé API : requêtes/s par status, latence P50/P95, trafic par endpoint. |

> La datasource Postgres lit son mot de passe depuis le Docker Secret
> `postgres_password` via `$__file{/run/secrets/postgres_password}` (aucun
> mot de passe en clair dans le provisioning).
>
> **Pour la démo**, ouvrir *SOC Verdicts* : il se peuple dès le premier scan
> Graph (les verdicts sont persistés en PostgreSQL par le pipeline). Le panel
> "Emails analysés" de *SOC Overview* ne compte que les appels HTTP `/analyze`,
> pas l'ingestion Graph — c'est attendu.

---

## Maintenance

### Voir les logs

```bash
docker compose logs -f orchestrator celery-worker
```

### Rotation des API keys

```bash
# Lister
curl -H "X-API-Key: …" http://localhost:8000/api/v1/admin/keys

# Révoquer
curl -X DELETE -H "X-API-Key: …" http://localhost:8000/api/v1/admin/keys/<ID>

# Créer une nouvelle clé
curl -X POST -H "X-API-Key: …" http://localhost:8000/api/v1/admin/keys -F "name=new-key"
```

### Mise à jour signatures ClamAV

Automatique via `freshclam` dans le conteneur ClamAV (toutes les heures).

### Backup PostgreSQL

```bash
docker compose exec postgres pg_dump -U postgres orchestrator_db | gzip > backup-$(date +%Y%m%d).sql.gz
```

---

## Pipeline d'analyse — diagnostic

| Symptôme | Vérifier |
|----------|----------|
| Verdicts ALLOW partout | YARA chargé ? `docker compose exec orchestrator ls yara-rules/` |
| ClamAV `down` | `docker compose logs clamav` (signature update peut prendre 2-3 min) |
| Scheduler ne tourne pas | Logs : `Azure non configuré` → vérifier `secrets/azure_*.txt` |
| /api/v1/stats vide | Pas d'analyse encore. Trigger un scan manuel |
| CAPE timeout | Augmenter `CAPE_TIMEOUT` dans `.env` |

---

## Sécurité — production

- [ ] Reverse proxy (Caddy / Traefik) devant l'API avec HTTPS Let's Encrypt
- [ ] IP allowlist sur `/api/v1/admin/*` au niveau du reverse proxy
- [ ] Firewall UFW : seulement 443 (HTTPS) et 22 (SSH) exposés
- [ ] SSH par clé uniquement (`PasswordAuthentication no`)
- [ ] Backups PostgreSQL automatisés (cron quotidien)
- [ ] Alertes Prometheus → Slack/Teams sur les pannes services
