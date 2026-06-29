# MailGuardianX

> **Défense anti-ransomware par email pour le secteur santé**
> Projet de fin d'année — Oteria Cyber School, promo B3 2025-2026

Pipeline multi-couches qui analyse les emails d'un tenant Microsoft 365 via Graph API, détecte les ransomwares dans les pièces jointes, et émet un verdict en quelques secondes — sans qu'aucune donnée patient ne quitte l'environnement de l'hôpital.

---

## Périmètre

| | |
|---|---|
| **Source d'ingestion** | Microsoft 365 / Outlook via Graph API (app-only, Client Credentials). **Unique source.** Pas d'agent sur les postes, pas de parser EML local, pas de plugin Gmail/Outlook. |
| **Scope de détection** | Anti-ransomware en **pièce jointe** (extension, macro, signatures YARA/ClamAV, IOC MISP, détonation CAPE). |
| **Base de données** | PostgreSQL (pas SQLite). |
| **Hors-scope actuel** | Détection phishing-texte (homoglyphes, mots-clés, analyse d'URLs, VirusTotal/URLScan) — prévu **après** la première démo. |

> Toute mention de SQLite, parser EML, agent poste ou plugin mail dans d'anciens documents est **obsolète** : seule l'ingestion tenant M365/Graph fait foi.

---

## Pourquoi

Les hôpitaux sont la cible #1 des ransomwares. Le vecteur principal : email avec pièce jointe piégée. Les solutions du marché (Proofpoint, Fortinet…) coûtent **10 000 à 50 000 €/an**, sont opaques, et souvent cloud-first — incompatible avec les contraintes RGPD des données patient.

MailGuardianX propose une alternative :

- **Open source**, zéro licence propriétaire (GPL v3)
- **Auto-hébergeable** sur le serveur de l'hôpital
- **Métadonnées uniquement** sortent du SI hospitalier (hash SHA256 + headers, jamais le corps d'email)
- **Tenant-level** via Microsoft Graph API — pas d'agent à installer sur les postes

---

## Architecture

```
Microsoft 365 tenant
       │
       │  (Graph API, app-only Client Credentials)
       ▼
APScheduler (scan différentiel toutes les 15min)
       │
       ▼
GraphIngestor — télécharge emails + pièces jointes
       │
       ▼
┌─────────────────────────────────────────────────┐
│  Orchestrateur FastAPI                          │
│                                                 │
│   1. Redis cache       (< 5ms)                  │
│   2. Heuristique       (< 10ms)                 │
│   3. YARA in-memory    (< 100ms, thread pool)   │
│   4. ClamAV (clamd)    (< 500ms)                │
│   5. MISP threat intel (< 1s)                   │
│   6. CAPE Sandbox      (2-10min, via Celery)    │
│                                                 │
│   Chaque étape peut court-circuiter avec BLOCK  │
└─────────────────────────────────────────────────┘
       │
       ▼
Verdict + IOCs → PostgreSQL (JSONB rapports CAPE)
       │
       ▼
Prometheus → Grafana (dashboard SOC)
```

### Pipeline cumulatif

| Étape | Service | Latence | Rôle |
|------:|--------|--------:|------|
| 1 | **Redis** | < 5ms | Hash déjà vu → verdict instantané |
| 2 | **Heuristique** | < 10ms | Extension, double extension, MIME mismatch, SPF/DKIM/DMARC, patterns santé |
| 3 | **YARA** | < 100ms | 7+ règles ransomware (CryptoAPI, shadow copies, dropper macro/LNK…) |
| 4 | **ClamAV** | < 500ms | Signatures connues (main.cvd + daily.cvd) |
| 5 | **MISP** | < 1s | Threat intel — IOCs, campagnes, tags |
| 6 | **CAPE** | 2-10min | Analyse dynamique en VM Windows isolée, réseau coupé d'Internet (INetSim) |

### Deux topologies de déploiement

CAPE peut tourner de deux façons, au choix :

- **Un seul serveur** — CAPE en conteneur Docker (`internal: true` + INetSim), profil `sandbox` du compose. Demande un hôte qui expose la virtualisation imbriquée au conteneur.
- **Deux machines** — l'orchestrateur d'un côté, une sandbox CAPE dédiée de l'autre (installation native, pas de conteneur). C'est la configuration recommandée et celle qui a été déployée pour ce projet : elle évite la dépendance à la virtualisation imbriquée sur la machine orchestrateur, et isole la détonation — qui exécute volontairement du code potentiellement malveillant — sur sa propre machine.

Détail des deux options : [GUIDE-DEPLOIEMENT.md](GUIDE-DEPLOIEMENT.md#choisir-sa-topologie).

---

## Stack technique

| Composant | Rôle |
|-----------|------|
| FastAPI (Python 3.11, async) | API orchestrateur |
| PostgreSQL 16 + SQLAlchemy 2.0 async | Stockage verdicts + Alembic migrations |
| Redis 7 | Cache hash, rate limit, broker Celery |
| Celery | Tâches longues (CAPE) |
| YARA (yara-python) | Détection par patterns |
| ClamAV (clamd) | AV signatures |
| MISP | Threat intelligence |
| CAPE Sandbox v2 | Analyse comportementale dynamique (conteneur en un seul serveur, installation native sur machine dédiée en déploiement deux machines) |
| Azure Identity + Microsoft Graph SDK | Auth app-only sur tenant M365 |
| APScheduler | Scans automatiques |
| Prometheus + Grafana | Observabilité |
| Docker Compose v2 | Orchestration |

---

## Démarrage rapide

### Pré-requis

- Ubuntu Server 22.04 ou 24.04 LTS (recommandé : 64 Go RAM, 32 cœurs, 2 To)
- Docker Engine ≥ 24.0 + Docker Compose v2
- Application Azure AD avec permissions Graph `Mail.Read` + `User.Read.All` (admin consent)

### Installation

```bash
git clone https://github.com/f3n999/SandBox.git mailguardianx
cd mailguardianx

# Génère tous les secrets Docker
chmod +x scripts/setup-secrets.sh
./scripts/setup-secrets.sh

# Remplir les 3 secrets Azure AD
nano secrets/azure_tenant_id.txt
nano secrets/azure_client_id.txt
nano secrets/azure_client_secret.txt

# Variables non-secrètes
cp .env.example .env
nano .env   # activer SCHEDULE_ENABLED=true

# Démarrer la stack — un seul serveur (CAPE en conteneur) :
docker compose --profile sandbox up -d
# ou, en déploiement deux machines (recommandé, voir GUIDE-DEPLOIEMENT.md) :
#   définir CAPE_API_URL dans .env vers l'IP de la machine sandbox, puis :
# docker compose up -d

# Appliquer les migrations DB
docker compose exec orchestrator alembic upgrade head

# Créer la première clé API admin
curl -X POST http://localhost:8000/api/v1/admin/keys \
     -F "name=bootstrap" -F "scopes=analyze,upload,admin"
```

Voir [GUIDE-DEPLOIEMENT.md](GUIDE-DEPLOIEMENT.md) pour la procédure complète : les deux topologies de déploiement, la sandbox CAPE dédiée pas à pas, et la récupération des tokens MISP/CAPE après premier boot.

---

## Structure du repo

```
.
├── orchestrator/                # Application Python
│   ├── api/main.py              # Routes FastAPI + lifespan
│   ├── celery_app.py            # App Celery (workers CAPE)
│   ├── core/
│   │   ├── config.py            # Config + Docker Secrets
│   │   └── heuristics.py        # Moteur de scoring rapide
│   ├── db/session.py            # Session SQLAlchemy 2.0 async
│   ├── ingestion/
│   │   ├── graph_client.py      # Microsoft Graph API (app-only)
│   │   ├── graph_ingestor.py    # Boucle scan tenant → pipeline
│   │   └── scheduler.py         # APScheduler
│   ├── models/
│   │   ├── database.py          # Modèles SQLAlchemy (JSONB, indexes GIN)
│   │   └── schemas.py           # Schemas Pydantic (API contracts)
│   ├── services/
│   │   ├── auth.py              # API keys bcrypt
│   │   ├── cache.py             # Redis
│   │   ├── cape_client.py       # CAPE Sandbox async
│   │   ├── clamav_client.py     # ClamAV via clamd
│   │   ├── misp_client.py       # MISP threat intel
│   │   ├── orchestrator.py      # Cerveau du pipeline
│   │   ├── stats.py             # Stats PostgreSQL pour dashboard
│   │   └── yara_scanner.py      # YARA in-memory
│   ├── tasks/cape_tasks.py      # Tâches Celery
│   └── tests/                   # Unit + integration + E2E
├── alembic/                     # Migrations DB
├── yara-rules/                  # Règles YARA ransomware
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/                 # Datasources + dashboards JSON
├── scripts/
│   ├── init-db.sql              # Init PostgreSQL au premier boot
│   └── setup-secrets.sh         # Génération Docker Secrets
├── secrets/                     # Fichiers de secrets (gitignored)
├── docker-compose.yml           # Stack complète
├── Dockerfile                   # Multi-stage (builder/prod/worker/dev)
├── requirements.txt
└── GUIDE-DEPLOIEMENT.md
```

---

## API publique (extrait)

| Méthode | Endpoint | Rôle |
|---------|----------|------|
| GET | `/` | Info service |
| GET | `/health` | État réel de chaque service (Redis, CAPE, MISP, ClamAV, YARA, scheduler) |
| GET | `/metrics` | Endpoint Prometheus |
| POST | `/api/v1/analyze` | Analyse metadata-only (auth requise) |
| POST | `/api/v1/upload` | Upload PJ → YARA + ClamAV + CAPE (synchrone) |
| POST | `/api/v1/upload/async` | Idem en mode Celery (retourne `celery_task_id`) |
| GET | `/api/v1/verdict/{task_id}` | Verdict caché par task_id |
| GET | `/api/v1/celery/{job_id}` | Statut/résultat d'une tâche Celery |
| GET | `/api/v1/stats?window_hours=24` | Stats SOC (PostgreSQL) |
| GET | `/api/v1/sessions` | Historique des sessions de scan |
| POST | `/api/v1/scan/trigger` | Déclenche un scan Graph manuel |
| POST | `/api/v1/whitelist/{sha256}` | Whitelist un hash |
| POST | `/api/v1/blacklist/{sha256}` | Blacklist un hash |
| POST | `/api/v1/admin/keys` | Créer une API key (bcrypt) |
| GET | `/api/v1/admin/keys` | Lister les API keys actives |
| DELETE | `/api/v1/admin/keys/{id}` | Révoquer une clé |

Documentation interactive : `https://serveur:8000/docs` (Swagger UI).

---

## Conformité RGPD / Santé

| Principe | Implémentation |
|----------|----------------|
| Minimisation des données | Hash SHA256 + métadonnées techniques uniquement transmis au backend |
| Pas de données patient | Corps d'email, champs patients, noms → jamais transmis |
| Chiffrement en transit | TLS partout (HTTPS, asyncpg SSL, Redis password) |
| Suppression après analyse | Fichiers envoyés à CAPE supprimés après verdict (TTL configurable) |
| Restriction d'accès | API keys bcrypt + scopes vérifiés + rate limiting par source |
| Traçabilité | `scan_sessions` + `email_analyses` en PostgreSQL avec timestamps |
| Réseau isolé | CAPE n'a jamais accès au vrai Internet (INetSim simule les réponses) ; en déploiement deux machines, la détonation tourne sur une machine séparée de l'orchestrateur |
| Secrets | Docker Secrets uniquement (pas d'env vars sensibles, pas de fichiers committés) |

---

## Tests

```bash
# Tests unitaires
pytest orchestrator/tests/unit -v

# Tests intégration (services mockés)
pytest orchestrator/tests/integration -v

# Tests E2E sur l'API
pytest orchestrator/tests/e2e -v

# Tout
pytest
```

---

## Sécurité — production

- Reverse proxy HTTPS (Caddy/Traefik) devant l'API
- IP allowlist sur `/api/v1/admin/*`
- Firewall UFW : seulement 443 + 22 exposés
- SSH par clé uniquement (`PasswordAuthentication no`)
- Backups PostgreSQL automatisés
- Alertes Prometheus → Slack/Teams

Voir [GUIDE-DEPLOIEMENT.md](GUIDE-DEPLOIEMENT.md) section *Sécurité — production*.

---

## Équipe

**Oteria Cyber School — Promo B3 2025-2026**

Projet collectif — Matthieu, Mohammed, Michael, Thibault, Tess.

---

## Licence

[GNU General Public License v3.0](LICENSE)
