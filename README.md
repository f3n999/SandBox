# 🛡️ Défense Anti-Ransomware — Sécurité Email pour le Secteur Santé

> **Mission Sandboxing 2025–2026** — Oteria Cyber School B3  
> Détection de ransomware par email avec analyse dynamique et threat intelligence, conçue pour le milieu hospitalier, déployable sans licence propriétaire.

---

## TL;DR

Une **brique de sécurité email anti-ransomware** pour les hôpitaux :

- **Backend d'orchestration** (FastAPI) hébergé chez le prestataire
- **Agents légers** déployés sur les postes de l'hôpital (Windows)
- **Analyse en cascade** : Cache Redis → Heuristique → MISP → CAPE Sandbox
- **RGPD-compliant** : seules les métadonnées et hash sortent de l'hôpital
- **Open source** : zéro licence propriétaire, stack 100% libre

---

## Le problème

Les établissements de santé sont les cibles prioritaires des ransomwares. Le vecteur principal : l'email avec pièce jointe piégée.

Les solutions du marché (Proofpoint, Fortinet…) coûtent 10k–50k €/an, sont opaques, et souvent cloud-first — incompatible avec les données patient. Un hôpital a besoin d'une solution qui :

1. Détecte les ransomwares (y compris zero-day) dans les pièces jointes
2. Ne fait **jamais** sortir de données patient du SI hospitalier
3. Fonctionne sans infrastructure lourde côté hôpital
4. Ne coûte rien en licences

---

## Architecture

```
    ┌─────────────────────────────────────────────────────────┐
    │               HÔPITAL (réseau interne)                  │
    │                                                         │
    │   ┌──────────────────────────────────────────────────┐  │
    │   │  Poste médecin/staff                             │  │
    │   │  ├── Outlook / client mail habituel              │  │
    │   │  └── Agent léger (extraction hash + métadonnées) │  │
    │   └──────────────────────────────────────────────────┘  │
    │            │                          ▲                  │
    │            │ Métadonnées + hash       │ Verdict          │
    │            │ (HTTPS/TLS)             │ (ALLOW/BLOCK)    │
    └────────────┼──────────────────────────┼──────────────────┘
                 │                          │
                 ▼                          │
    ┌─────────────────────────────────────────────────────────┐
    │            BACKEND (chez le prestataire)                 │
    │                                                         │
    │   ┌─────────────────────────────────────────────┐       │
    │   │          API FastAPI (Orchestrateur)         │       │
    │   │                                             │       │
    │   │  1. Redis Cache ──────── hash connu ?       │       │
    │   │     │ non                                   │       │
    │   │  2. Heuristique ──────── score de risque    │       │
    │   │     │ score intermédiaire                   │       │
    │   │  3. MISP Lookup ──────── IOC / campagne ?   │       │
    │   │     │ suspect                               │       │
    │   │  4. CAPE Sandbox ──────── exécution isolée  │       │
    │   │     │                                       │       │
    │   │  → Verdict final (ALLOW / BLOCK / QUARANTINE)│      │
    │   └─────────────────────────────────────────────┘       │
    │                                                         │
    │   ┌──────────┐  ┌───────┐  ┌──────────┐  ┌─────────┐  │
    │   │PostgreSQL│  │ Redis │  │   MISP   │  │  CAPE   │  │
    │   │(verdicts)│  │(cache)│  │(threat   │  │(sandbox)│  │
    │   │          │  │       │  │ intel)   │  │         │  │
    │   └──────────┘  └───────┘  └──────────┘  └─────────┘  │
    │                                                         │
    │   ┌────────────────────┐  ┌─────────────────────────┐  │
    │   │ Grafana (dashboard)│  │ Prometheus (métriques)  │  │
    │   └────────────────────┘  └─────────────────────────┘  │
    └─────────────────────────────────────────────────────────┘
```

### Pipeline de décision (cascade)

| Étape | Service | Latence | Rôle |
|-------|---------|---------|------|
| 1 | **Redis Cache** | < 5ms | Hash déjà analysé ? Verdict instantané |
| 2 | **Heuristique** | < 10ms | Score de risque (extension, macros, SPF/DKIM, patterns santé) |
| 3 | **MISP** | < 1s | IOCs connus, campagnes actives, tags ransomware |
| 4 | **CAPE Sandbox** | 2–10 min | Exécution dynamique en VM Windows isolée |

Chaque étape peut **court-circuiter** le pipeline : si le hash est en cache → verdict en 5ms, pas besoin des étapes suivantes.

---

## Flux de traitement

### Chemin rapide (métadonnées uniquement — RGPD-safe)

1. Email arrive sur le poste → l'agent détecte la pièce jointe
2. L'agent calcule le **SHA256** et collecte les **métadonnées** (expéditeur, taille, type MIME, SPF/DKIM/DMARC)
3. Envoi au backend via HTTPS → `POST /api/v1/analyze`
4. Le backend répond avec un verdict en < 1 seconde (cache + heuristique + MISP)
5. L'agent applique le verdict localement

**Aucune donnée patient ne quitte l'hôpital à cette étape.**

### Chemin profond (analyse CAPE — optionnel)

1. Si le score est intermédiaire, le backend renvoie `REQUEST_DEEP_ANALYSIS`
2. L'agent envoie la pièce jointe (pas le corps de l'email) → `POST /api/v1/upload`
3. CAPE exécute le fichier en VM Windows isolée
4. Analyse comportementale : chiffrement, shadow copies, injection, C2…
5. Verdict final renvoyé à l'agent

**Ce mode est optionnel et encadré** : uniquement les fichiers techniques, supprimés après analyse.

---

## Stack technique

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Orchestrateur** | FastAPI (Python 3.11) | API centrale, pipeline de décision |
| **Cache** | Redis 7 | Hash lookup instantané, rate limiting, réputation expéditeur |
| **Sandbox** | CAPEv2 | Analyse dynamique en VM Windows isolée |
| **Threat Intel** | MISP | Base d'IOCs, campagnes, enrichissement |
| **Base de données** | PostgreSQL 15 | Stockage verdicts, logs, métriques |
| **Base CAPE** | MongoDB 6 | Stockage rapports CAPE |
| **Base MISP** | MySQL 8 | Backend MISP |
| **Monitoring** | Grafana + Prometheus | Dashboard SOC, métriques |
| **Agent** | C# (.NET) ou Python | Client léger côté hôpital |

---

## Structure du projet

```
.
├── orchestrator/
│   ├── api/
│   │   └── main.py                 # FastAPI — endpoints + middleware
│   ├── core/
│   │   ├── config.py               # Configuration centralisée (pydantic-settings)
│   │   └── heuristics.py           # Moteur de scoring heuristique
│   ├── models/
│   │   ├── schemas.py              # Modèles Pydantic (validation entrées/sorties)
│   │   └── database.py             # Modèles SQLAlchemy (PostgreSQL)
│   ├── services/
│   │   ├── orchestrator.py         # Pipeline principal (cerveau du système)
│   │   ├── cache.py                # Service Redis
│   │   ├── cape_client.py          # Client CAPE async
│   │   └── misp_client.py          # Client MISP async
│   └── tests/
│       └── unit/
│           └── test_heuristics.py   # 18 tests unitaires
├── yara-rules/
│   └── ransomware_detection.yar    # 7 règles YARA ransomware
├── scripts/
│   └── init-db.sql                 # Initialisation PostgreSQL
├── docker-compose.yml              # Stack complète
├── Dockerfile                      # Multi-stage (dev + prod)
├── requirements.txt                # Dépendances Python (versions pinées)
├── .env.example                    # Template secrets (AUCUN secret en dur)
└── pyproject.toml                  # Config pytest
```

---

## Conformité RGPD / Santé

| Principe | Implémentation |
|----------|----------------|
| **Minimisation des données** | Seuls hash + métadonnées techniques envoyés au backend |
| **Pas de données patient** | Corps d'email, champs patients, noms → jamais transmis |
| **Chiffrement en transit** | Toute communication agent ↔ backend en HTTPS/TLS |
| **Suppression après analyse** | Fichiers envoyés à CAPE supprimés après verdict |
| **Restriction d'accès** | Auth par API key, rate limiting par agent, CORS restreint |
| **Traçabilité** | Logs structurés, stockage verdicts avec timestamps |
| **Chemin profond optionnel** | L'envoi de fichiers complets peut être désactivé par politique |

---

## API Endpoints

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/` | Info service |
| `GET` | `/health` | Health check réel (vérifie Redis, CAPE, MISP) |
| `POST` | `/api/v1/analyze` | Analyse email (métadonnées + hash) |
| `POST` | `/api/v1/upload` | Upload fichier pour CAPE (chemin profond) |
| `GET` | `/api/v1/verdict/{task_id}` | Récupérer un verdict |
| `GET` | `/api/v1/stats` | Statistiques SOC |
| `POST` | `/api/v1/whitelist/{sha256}` | Whitelist un hash (faux positif) |
| `POST` | `/api/v1/blacklist/{sha256}` | Blacklist un hash |
| `GET` | `/docs` | Documentation Swagger UI |

---

## Moteur heuristique

Le scoring prend en compte :

- **Extensions à haut risque** : `.exe`, `.dll`, `.vbs`, `.ps1`, `.hta`, `.lnk`, `.iso` → score 0.78–0.95
- **Doubles extensions** : `facture.pdf.exe` → +0.35
- **Macros activées** : `.docm`, `.xlsm` → +0.30
- **Archives chiffrées** : ZIP protégé par mot de passe → +0.25
- **MIME mismatch** : extension ≠ type MIME → +0.30
- **Taille suspecte** : EXE de 15KB (dropper) ou PDF de 200 octets (leurre)
- **Authentification email** : SPF/DKIM/DMARC fail → +0.15 à +0.40
- **Patterns santé** : domaines usurpés (ameli.fr, mssante.fr, ars.sante…) → +0.35
- **Expéditeurs suspects** : `invoice-payment@`, `urgent-notification@` → +0.20
- **Envoi de masse** : > 50 destinataires → +0.15

---

## Licence

**GNU General Public License v3.0** — Voir [LICENSE](LICENSE)

---

## Équipe

**Oteria Cyber School — Promotion B3 2025–2026**

---
