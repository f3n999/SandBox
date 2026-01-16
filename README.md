#  Défense Anti-Ransomware pour les Établissements de Santé

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)
![Status](https://img.shields.io/badge/status-in%20development-orange.svg)

##  Description

Architecture complète de sécurité email open source basée sur Docker, combinant :
- **Filtrage statique** (Rspamd, ClamAV)
- **Analyse comportementale dynamique** (CAPE Sandbox)
- **Threat Intelligence** (MISP)

Conçu pour protéger les données critiques de santé **sans surcoût de licence**, conforme **RGPD/Loi Ségur**.

---

##  Objectifs du Projet

| # | Objectif | Status |
|---|----------|--------|
| **O1** | Pipeline email end-to-end fonctionnel (< 10 min) | 🟡 En cours |
| **O2** | Détection zero-day viable (CAPE Sandbox) | 🟡 En cours |
| **O3** | Automation complète (Orchestrateur Python) | 🟡 En cours |
| **O4** | Conformité RGPD/Ségur respectée | 🟡 En cours |
| **O5** | Documentation production-ready | 🟡 En cours |
| **O6** | Démo vidéo convaincante (5-10 min) | 🔴 À faire |

---

##  Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      INTERNET / EMAIL                          │
└───────────────────┬──────────────────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────────────────────────┐
│                   MAIL SERVER (Mailcow)                        │
│  ┌──────────────────────────────────────────────────────┐      │
│  │ Postfix (MTA)  ──► Rspamd  ──► ClamAV              │      │
│  └──────────────┬──────────────────────────────────────┘      │
│                 │ Extraction pièces jointes                    │
└─────────────────┼──────────────────────────────────────────────┘
                  │
                  ▼
┌────────────────────────────────────────────────────────────────┐
│         ORCHESTRATEUR (Python FastAPI)                        │
│  • Hashing (SHA256, ssdeep)                                   │
│  • Heuristique décision                                       │
│  • CAPE API client                                            │
│  • MISP lookups & injections                                  │
│  • Verdict automatique                                        │
└───┬─────────────┬─────────────────────────────────────────┬───┘
    │             │                                         │
    ▼             ▼                                         ▼
┌─────────┐  ┌──────────────┐                      ┌──────────┐
│ MISP    │  │ CAPE Sandbox │                      │   Logs   │
│ Threat  │  │ VM Windows   │                      │ AES256   │
│ Intel   │  │ Detonation   │                      │ 90 jours │
└─────────┘  └──────────────┘                      └──────────┘
```

---

##  Quick Start

### Prérequis

- **Docker** 20.10+ & **Docker Compose** 2.0+
- **8 CPU cores** minimum
- **32GB RAM** minimum
- **500GB disque** SSD
- **Ubuntu 22.04 LTS** ou Debian 12

### Installation

```bash
# 1. Clone le repo
git clone https://github.com/f3n999/SandBox.git
cd SandBox

# 2. Configuration environnement
cp .env.example .env
nano .env  # Éditer les variables

# 3. Lancer l'infrastructure complète
docker-compose up -d

# 4. Vérifier les services
docker-compose ps

# 5. Accéder aux interfaces
# Mailcow: https://localhost:8443
# Orchestrateur API: http://localhost:8000/docs
# CAPE Sandbox: http://localhost:8080
# MISP: https://localhost:8443
```

---

##  Structure du Projet

```
SandBox/
├── orchestrator/          # API Python FastAPI
│   ├── app/
│   │   ├── main.py       # Point d'entrée
│   │   ├── models.py     # Modèles de données
│   │   ├── api/          # Endpoints REST
│   │   ├── core/         # Logique métier
│   │   │   ├── hashing.py
│   │   │   ├── heuristic.py
│   │   │   ├── cape_client.py
│   │   │   └── misp_client.py
│   │   └── utils/
│   ├── Dockerfile
│   └── requirements.txt
│
├── mail-infra/           # Infrastructure mail
│   ├── mailcow/          # Config Mailcow
│   ├── rspamd/           # Règles Rspamd
│   ├── clamav/           # Config ClamAV
│   └── docker-compose.yml
│
├── sandbox/              # CAPE Sandbox
│   ├── cape-config/
│   ├── yara-rules/       # Règles YARA custom
│   │   ├── ransomware.yar
│   │   ├── trojan.yar
│   │   └── obfuscation.yar
│   └── vm-snapshots/
│
├── threat-intel/         # MISP
│   ├── misp-config/
│   └── feeds/
│
├── docs/                 # Documentation
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── API.md
│   └── TROUBLESHOOTING.md
│
├── tests/                # Tests
│   ├── unit/
│   ├── integration/
│   └── e2e/
│
├── scripts/              # Scripts utilitaires
│   ├── deploy.sh
│   ├── backup.sh
│   └── test-samples.sh
│
├── docker-compose.yml    # Orchestration complète
├── .env.example          # Variables environnement
├── .gitignore
├── LICENSE
├── README.md
└── CONTRIBUTING.md
```

---

##  Configuration

### Variables d'environnement (.env)

```bash
# Mailcow
MAILCOW_HOSTNAME=mail.example.com
MAILCOW_ADMIN_USER=admin
MAILCOW_ADMIN_PASS=SecurePassword123!

# Orchestrateur
ORCHESTRATOR_PORT=8000
ORCHESTRATOR_SECRET_KEY=your-secret-key-here

# CAPE Sandbox
CAPE_API_URL=http://cape:8000
CAPE_API_TOKEN=your-cape-token

# MISP
MISP_URL=https://misp:8443
MISP_API_KEY=your-misp-api-key
MISP_VERIFY_SSL=false

# Database
POSTGRES_USER=ransomware_defense
POSTGRES_PASSWORD=SecureDBPassword123!
POSTGRES_DB=orchestrator_db

# Logs
LOG_LEVEL=INFO
LOG_RETENTION_DAYS=90
```

---

##  Tests

```bash
# Tests unitaires
cd orchestrator
pytest tests/unit/ -v

# Tests intégration
pytest tests/integration/ -v

# Tests end-to-end
pytest tests/e2e/ -v

# Test avec samples malware
./scripts/test-samples.sh
```

---

##  API Documentation

Une fois l'orchestrateur lancé, accède à la documentation interactive :

**Swagger UI** : http://localhost:8000/docs  
**ReDoc** : http://localhost:8000/redoc

### Endpoints principaux

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/v1/analyze` | POST | Analyser un fichier suspect |
| `/api/v1/verdict/{task_id}` | GET | Récupérer le verdict d'une analyse |
| `/api/v1/quarantine` | POST | Mettre en quarantaine un email |
| `/api/v1/stats` | GET | Statistiques de détection |
| `/api/v1/health` | GET | Health check |

---

##  Sécurité

-  **Zéro donnée patient hors-premise** (100% on-premise)
-  **Logs chiffrés AES256**
-  **Rétention 90 jours** avec purge automatique
-  **RGPD by design**
-  **Loi Ségur conforme**
- **TLS/SSL** sur toutes les communications

---

##  Roadmap

### ✅ Phase 1 : Fondations 
- [x] Setup lab & architecture decisions
- [x] Repository GitHub initialisé
- [x] Documentation de base

### 🟡 Phase 2 : Infrastructure Mail 
- [ ] Mailcow déployé
- [ ] Rspamd configuré
- [ ] ClamAV opérationnel

### 🟡 Phase 3 : Sandbox & Threat Intel 
- [ ] CAPE Sandbox setup
- [ ] Règles YARA v1 (5 règles)
- [ ] MISP instance lancée

### 🔴 Phase 4 : Orchestrateur 
- [ ] API FastAPI complète
- [ ] Hashing + heuristique
- [ ] Intégration CAPE

### 🔴 Phase 5 : Intégration 
- [ ] Pipeline end-to-end
- [ ] Tests intégration

### 🔴 Phase 6 : Intelligence 
- [ ] Boucle MISP feedback
- [ ] Règles YARA v2

### 🔴 Phase 7 : Démo & Doc 
- [ ] Vidéo démo
- [ ] Documentation finale
- [ ] Playbook Ansible

---


**École** : Oteria Cyber School B3 - Levallois-Perret, Île-de-France  

---


### Workflow Git

```bash
# 1. Créer une branche feature
git checkout -b feature/nom-de-ta-feature

# 2. Commit avec message clair
git commit -m "feat(orchestrator): add hashing logic"

# 3. Push vers ton fork
git push origin feature/nom-de-ta-feature

# 4. Créer une Pull Request
```

### Convention de commits

- `feat:` nouvelle fonctionnalité
- `fix:` correction de bug
- `docs:` documentation
- `test:` ajout de tests
- `refactor:` refactoring code
- `chore:` tâches maintenance

---

##  License

Ce projet est sous licence **GPL-3.0** - voir [LICENSE](LICENSE) pour détails.

---

##  Ressources

- **CAPE Sandbox** : https://capesandbox.com/docs/
- **YARA** : https://yara.readthedocs.io/
- **Rspamd** : https://rspamd.com/doc/
- **MISP** : https://www.misp-project.org/
- **FastAPI** : https://fastapi.tiangolo.com/

---

##  Support

- **Issues GitHub** : [Créer une issue](https://github.com/f3n999/SandBox/issues)
- **Discussions** : [GitHub Discussions](https://github.com/f3n999/SandBox/discussions)
- **Email équipe** : oteria-b3-ransomware@example.com

---

