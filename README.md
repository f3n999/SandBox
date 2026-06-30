# 🛡️ MailGuardianX

> **Défense anti-ransomware par email pour le secteur santé**
> Projet de fin d'année, Oteria Cyber School, promo B3 2025-2026

> **Email-borne ransomware defense for the healthcare sector**
> Final-year project, Oteria Cyber School, B3 class of 2025-2026

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-async-009688)
![Docker](https://img.shields.io/badge/Docker-Compose%20v2-2496ED)
![License](https://img.shields.io/badge/License-GPLv3-green)

## 📑 Sommaire / Contents

- [💡 En deux mots / In a nutshell](#-en-deux-mots--in-a-nutshell)
- [🚨 Le problème / The problem](#-le-problème--the-problem)
- [🧩 Ce qu'on a construit / What we built](#-ce-quon-a-construit--what-we-built)
- [🎯 Périmètre / Scope](#-périmètre-ce-qui-est-dedans-et-ce-qui-ne-lest-pas--scope-what-is-in-and-what-is-not)
- [🔄 Comment ça marche / How it works](#-comment-ça-marche-la-chaîne-danalyse--how-it-works-the-analysis-chain)
  - [📊 Le détail des étapes / The cumulative pipeline](#-le-détail-des-étapes--the-cumulative-pipeline)
  - [🎣 Détection de phishing et RGPD / Phishing detection and GDPR](#-la-détection-de-phishing-et-pourquoi-elle-respecte-le-rgpd--phishing-detection-and-why-it-respects-gdpr)
  - [🧭 Deux façons de déployer / Two ways to deploy](#-deux-façons-de-déployer-le-projet--two-ways-to-deploy)
- [🧰 Stack technique / Tech stack](#-stack-technique--tech-stack)
- [🚀 Démarrage rapide / Quick start](#-démarrage-rapide--quick-start)
- [📁 Structure du repo / Repo structure](#-structure-du-repo--repo-structure)
- [🔌 L'API publique / The public API](#-lapi-publique-extrait--the-public-api-excerpt)
- [🔐 Conformité RGPD / GDPR compliance](#-conformité-rgpd-et-santé--gdpr-and-healthcare-compliance)
- [🧪 Tests](#-tests)
- [🔒 Sécurité en production / Production security](#-sécurité-en-production--production-security)
- [👥 Équipe / Team](#-équipe--team)
- [📄 Licence / License](#-licence--license)

## 💡 En deux mots / In a nutshell

**FR.** MailGuardianX surveille la boîte mail d'un hôpital et bloque les emails piégés avant qu'ils ne fassent des dégâts. Concrètement, il se branche sur la messagerie Microsoft 365 de l'établissement, récupère les nouveaux emails et leurs pièces jointes, les passe dans une série de contrôles de sécurité, et rend un verdict en quelques secondes : sûr, suspect, ou dangereux. Tout ça sans qu'aucune information sur les patients ne sorte de l'hôpital. Seules des données techniques anonymes (l'empreinte d'un fichier, pas son contenu) sont analysées.

Pour situer : un ransomware, c'est un logiciel malveillant qui chiffre les fichiers d'une organisation et réclame une rançon pour les débloquer. Les hôpitaux en sont une cible privilégiée, et le point d'entrée le plus courant reste la pièce jointe d'un email. C'est exactement ce que MailGuardianX cherche à arrêter.

**EN.** MailGuardianX watches a hospital's mailbox and blocks booby-trapped emails before they can do harm. In practice, it connects to the organization's Microsoft 365 email, pulls in new messages and their attachments, runs them through a series of security checks, and returns a verdict within seconds: safe, suspicious, or dangerous. All of this without any patient information ever leaving the hospital. Only anonymous technical data (a file's fingerprint, not its content) is analyzed.

For context: ransomware is malicious software that encrypts an organization's files and demands a ransom to unlock them. Hospitals are a prime target, and the most common entry point is still an email attachment. That is exactly what MailGuardianX is built to stop.

## 🚨 Le problème / The problem

**FR.** Les hôpitaux sont aujourd'hui la cible numéro un des attaques par ransomware, et le vecteur principal reste l'email avec une pièce jointe piégée. Les solutions du marché existent (Proofpoint, Fortinet, et d'autres), mais elles coûtent entre 10 000 et 50 000 euros par an, restent des boîtes noires dont on ne sait pas vraiment comment elles décident, et sont souvent pensées pour le cloud d'abord. Ce dernier point pose un vrai problème avec les données patient, soumises au RGPD, qui ne devraient pas transiter par des serveurs externes.

**EN.** Hospitals are today the number-one target for ransomware attacks, and the main vector is still an email with a booby-trapped attachment. Commercial solutions exist (Proofpoint, Fortinet, and others), but they cost between 10,000 and 50,000 euros per year, remain black boxes whose decision-making is opaque, and are often cloud-first by design. That last point is a real issue for patient data, which falls under GDPR and should not pass through external servers.

## 🧩 Ce qu'on a construit / What we built

**FR.** MailGuardianX est une alternative open source à ces solutions. Trois choix de conception résument l'approche :

- **Open source et sans licence à payer** (GPL v3). Le code est lisible, vérifiable, et n'enferme personne dans un contrat.
- **Auto-hébergé.** Le système tourne sur le serveur de l'hôpital, pas dans un cloud tiers. L'établissement garde la main sur ses données.
- **Le minimum de données qui sort.** Seules des métadonnées techniques quittent le système d'information de l'hôpital : l'empreinte numérique d'un fichier (son hash SHA256) et les en-têtes de l'email. Jamais le corps de l'email, jamais un nom de patient.

Côté branchement, rien à installer sur les postes des employés. MailGuardianX se connecte directement au niveau du compte Microsoft 365 de l'établissement (le « tenant ») via l'API officielle de Microsoft, appelée Graph. C'est l'hôpital qui autorise cet accès une fois, et le système fait le reste tout seul.

**EN.** MailGuardianX is an open-source alternative to those solutions. Three design choices sum up the approach:

- **Open source, no license fee** (GPL v3). The code is readable, auditable, and locks no one into a contract.
- **Self-hosted.** The system runs on the hospital's own server, not in a third-party cloud. The organization keeps control of its data.
- **The least possible data leaves.** Only technical metadata leaves the hospital's information system: a file's digital fingerprint (its SHA256 hash) and the email headers. Never the email body, never a patient name.

On the integration side, there is nothing to install on staff workstations. MailGuardianX connects directly at the level of the organization's Microsoft 365 account (the "tenant") through Microsoft's official API, called Graph. The hospital grants this access once, and the system handles the rest on its own.

## 🎯 Périmètre, ce qui est dedans et ce qui ne l'est pas / Scope, what is in and what is not

**FR.** Le périmètre est volontairement resserré pour cette première version, histoire de faire une chose et de bien la faire.

| | |
| --- | --- |
| Source des emails | Microsoft 365 / Outlook via l'API Graph, en mode application (Client Credentials). C'est l'unique source. Pas d'agent installé sur les postes, pas de lecteur de fichiers EML en local, pas de plugin Gmail ou Outlook. |
| Ce qu'on détecte | Les ransomwares cachés dans les pièces jointes (par leur extension, leurs macros, des signatures YARA et ClamAV, des indicateurs MISP, et une détonation en sandbox CAPE), plus les mots-clés de phishing connus dans le sujet et le corps du message. |
| Base de données | PostgreSQL (et non SQLite). |
| Pas encore couvert | Les homoglyphes (caractères qui se ressemblent pour tromper l'œil), l'analyse des URLs, VirusTotal et URLScan. C'est prévu pour après la première démo. |

**EN.** The scope is deliberately narrow for this first version, the idea being to do one thing and do it well.

| | |
| --- | --- |
| Email source | Microsoft 365 / Outlook through the Graph API, in application mode (Client Credentials). This is the only source. No agent installed on workstations, no local EML file reader, no Gmail or Outlook plugin. |
| What we detect | Ransomware hidden in attachments (by extension, macros, YARA and ClamAV signatures, MISP indicators, and detonation in a CAPE sandbox), plus known phishing keywords in the subject and body. |
| Database | PostgreSQL (not SQLite). |
| Not covered yet | Homoglyphs (look-alike characters used to fool the eye), URL analysis, VirusTotal and URLScan. Planned for after the first demo. |

> **FR.** Si vous croisez d'anciens documents qui parlent de SQLite, d'un lecteur EML, d'un agent sur les postes ou d'un plugin mail, ignorez-les : ils sont obsolètes. Seule l'ingestion via le tenant M365 et l'API Graph fait foi.
> **EN.** If you come across older documents mentioning SQLite, an EML reader, an endpoint agent or a mail plugin, ignore them: they are obsolete. Only ingestion through the M365 tenant and the Graph API is authoritative.

## 🔄 Comment ça marche, la chaîne d'analyse / How it works, the analysis chain

**FR.** Le cœur de MailGuardianX, c'est une chaîne de contrôles que chaque pièce jointe traverse les uns après les autres. L'idée est simple et efficace : on commence par les vérifications les plus rapides et les moins coûteuses, et on ne passe à l'étape suivante, plus lente mais plus poussée, que si le doute persiste. Dès qu'une étape juge un fichier dangereux, elle peut tout arrêter et émettre un verdict de blocage, sans aller plus loin. C'est ce qui permet de rendre un avis en quelques millisecondes dans la grande majorité des cas, tout en gardant une analyse en profondeur pour les fichiers vraiment suspects.

Voici le parcours, du plus rapide au plus lent :

```
Microsoft 365 tenant
       |
       |  (API Graph, mode application)
       v
APScheduler : un scan toutes les 15 minutes, uniquement les nouveaux emails
       |
       v
GraphIngestor : télécharge les emails et leurs pièces jointes
       |
       v
+-------------------------------------------------+
|  Orchestrateur FastAPI (le chef d'orchestre)    |
|                                                 |
|   1. Cache Redis       (< 5 ms)                 |
|   2. Heuristique       (< 10 ms)                |
|   3. YARA en mémoire   (< 100 ms)               |
|   4. ClamAV            (< 500 ms)               |
|   5. MISP threat intel (< 1 s)                  |
|   6. Sandbox CAPE      (2 à 10 min)             |
|                                                 |
|   Chaque étape peut tout stopper avec un BLOCK  |
+-------------------------------------------------+
       |
       v
Verdict + indicateurs vers PostgreSQL
       |
       v
Prometheus vers Grafana (le tableau de bord du SOC)
```

Étape par étape, en clair :

1. **⚡ Cache Redis.** A-t-on déjà vu ce fichier exact récemment ? Si oui, on connaît déjà la réponse, verdict immédiat.
2. **🔍 Heuristique.** Une série de règles simples et rapides : l'extension est-elle louche, y a-t-il une double extension (le classique `facture.pdf.exe`), le type de fichier annoncé correspond-il au vrai contenu, les protections anti-usurpation de l'email (SPF, DKIM, DMARC) sont-elles valides, le message contient-il des mots-clés de phishing connus.
3. **🧬 YARA.** Des règles qui cherchent des motifs typiques de ransomware à l'intérieur du fichier (appels à l'API de chiffrement de Windows, suppression des sauvegardes système, macros et raccourcis piégés). Sept règles maison tournent ici, directement en mémoire pour aller vite.
4. **🦠 ClamAV.** L'antivirus open source, qui compare le fichier à une base de signatures de malwares déjà connus.
5. **🌐 MISP.** Une base de renseignement sur les menaces (threat intelligence) : ce fichier ou cet expéditeur sont-ils associés à une campagne d'attaque déjà répertoriée.
6. **💣 Sandbox CAPE.** L'artillerie lourde. Le fichier est ouvert et exécuté pour de vrai, mais dans une machine virtuelle Windows totalement isolée et coupée d'Internet. On observe son comportement : tente-t-il de chiffrer des fichiers, de contacter un serveur, de se propager. C'est lent (de 2 à 10 minutes) mais c'est le seul moyen de démasquer un malware inconnu de toutes les bases.

**EN.** The heart of MailGuardianX is a chain of checks that every attachment passes through one after another. The idea is simple and effective: we start with the fastest and cheapest checks, and only move on to the next, slower but more thorough step if doubt remains. As soon as a step decides a file is dangerous, it can stop everything and issue a block verdict without going further. This is what makes it possible to return an opinion in a few milliseconds in the vast majority of cases, while keeping a deep analysis for the genuinely suspicious files.

Here is the journey, from fastest to slowest:

```
Microsoft 365 tenant
       |
       |  (Graph API, application mode)
       v
APScheduler: one scan every 15 minutes, new emails only
       |
       v
GraphIngestor: downloads emails and their attachments
       |
       v
+-------------------------------------------------+
|  FastAPI orchestrator (the conductor)           |
|                                                 |
|   1. Redis cache       (< 5 ms)                 |
|   2. Heuristics        (< 10 ms)                |
|   3. YARA in memory    (< 100 ms)               |
|   4. ClamAV            (< 500 ms)               |
|   5. MISP threat intel (< 1 s)                  |
|   6. CAPE sandbox      (2 to 10 min)            |
|                                                 |
|   Any step can stop everything with a BLOCK     |
+-------------------------------------------------+
       |
       v
Verdict + indicators to PostgreSQL
       |
       v
Prometheus to Grafana (the SOC dashboard)
```

Step by step, in plain terms:

1. **⚡ Redis cache.** Have we already seen this exact file recently? If so, we already know the answer, instant verdict.
2. **🔍 Heuristics.** A set of simple, fast rules: is the extension shady, is there a double extension (the classic `invoice.pdf.exe`), does the declared file type match the real content, are the email's anti-spoofing protections (SPF, DKIM, DMARC) valid, does the message contain known phishing keywords.
3. **🧬 YARA.** Rules that look for patterns typical of ransomware inside the file (calls to Windows encryption APIs, deletion of system backups, booby-trapped macros and shortcuts). Seven in-house rules run here, directly in memory for speed.
4. **🦠 ClamAV.** The open-source antivirus, which compares the file against a database of already-known malware signatures.
5. **🌐 MISP.** A threat intelligence database: is this file or sender associated with an already-catalogued attack campaign.
6. **💣 CAPE sandbox.** The heavy artillery. The file is actually opened and run, but inside a fully isolated Windows virtual machine cut off from the internet. We watch its behavior: does it try to encrypt files, contact a server, spread. It is slow (2 to 10 minutes) but it is the only way to unmask malware unknown to every database.

### 📊 Le détail des étapes / The cumulative pipeline

| Étape / Step | Service | Latence / Latency | Rôle / Role |
| --- | --- | --- | --- |
| 1 | Redis | < 5 ms | Hash déjà vu, verdict instantané / Hash already seen, instant verdict |
| 2 | Heuristique / Heuristics | < 10 ms | Extension, double extension, MIME mismatch, SPF/DKIM/DMARC, patterns santé, mots-clés phishing |
| 3 | YARA | < 100 ms | 7 règles ransomware (CryptoAPI, shadow copies, dropper macro/LNK) |
| 4 | ClamAV | < 500 ms | Signatures connues (main.cvd + daily.cvd) |
| 5 | MISP | < 1 s | Threat intel : IOCs, campagnes, tags |
| 6 | CAPE | 2 à 10 min / 2 to 10 min | Analyse dynamique en VM Windows isolée, réseau coupé (INetSim) / Dynamic analysis in an isolated Windows VM, network cut off (INetSim) |

### 🎣 La détection de phishing, et pourquoi elle respecte le RGPD / Phishing detection, and why it respects GDPR

**FR.** En plus de l'analyse des pièces jointes, l'étape heuristique lit le texte de l'email pour repérer les formulations classiques du phishing : l'urgence artificielle (« votre compte sera fermé dans 24h »), la demande de mot de passe, l'invitation à cliquer tout de suite. Ces formulations sont rangées en six catégories dans le fichier `orchestrator/core/phishing_keywords.py`. La logique de scoring est calibrée pour éviter les fausses alertes : trois mots-clés ou plus donnent un score élevé, deux un score moyen, et un seul mot ne déclenche rien, parce que beaucoup de termes (« urgent », « facture ») sont parfaitement normaux dans un échange professionnel.

Le point crucial côté RGPD : ce score est calculé localement, au moment de l'ingestion, sur le sujet et l'aperçu du corps tels que reçus de Microsoft Graph, avant que quoi que ce soit ne continue dans la chaîne. Seul le résultat franchit la frontière vers la base de données et les tableaux de bord : un score entre 0 et 1, et des noms de catégorie comme `"urgence"` ou `"finance"`. Le texte du sujet, le corps du message et le mot précis qui a déclenché l'alerte ne sont jamais stockés ni transmis. C'est le même principe de minimisation que pour les pièces jointes, où l'on ne garde que l'empreinte SHA256 et jamais le contenu.

**EN.** On top of attachment analysis, the heuristic step reads the email text to spot classic phishing wording: artificial urgency ("your account will be closed in 24 hours"), password requests, invitations to click right away. These phrasings are grouped into six categories in the file `orchestrator/core/phishing_keywords.py`. The scoring logic is tuned to avoid false alarms: three keywords or more give a high score, two a medium score, and a single word triggers nothing, because many terms ("urgent", "invoice") are perfectly normal in a professional exchange.

The crucial point for GDPR: this score is computed locally, at ingestion time, on the subject and body preview as received from Microsoft Graph, before anything moves further down the chain. Only the result crosses the boundary into the database and the dashboards: a score between 0 and 1, and category names such as `"urgence"` or `"finance"`. The subject text, the message body and the exact word that triggered the alert are never stored or transmitted. This is the same minimization principle as for attachments, where we keep only the SHA256 fingerprint and never the content.

### 🧭 Deux façons de déployer le projet / Two ways to deploy

**FR.** La sandbox CAPE peut tourner de deux manières, au choix selon le matériel disponible.

- **Sur un seul serveur.** CAPE tourne dans un conteneur Docker isolé (option `internal: true` plus INetSim qui simule Internet), via le profil `sandbox` du fichier compose. Cette option demande un serveur capable d'exposer la virtualisation imbriquée au conteneur, ce qui n'est pas toujours évident à configurer.
- **Sur deux machines.** L'orchestrateur d'un côté, et une sandbox CAPE dédiée de l'autre, installée nativement (sans conteneur). C'est la configuration recommandée, et celle qui a réellement été déployée pour ce projet. Elle a deux avantages : elle évite de dépendre de la virtualisation imbriquée sur la machine principale, et elle isole physiquement la détonation, qui consiste après tout à exécuter volontairement du code potentiellement malveillant, sur une machine à part.

**EN.** The CAPE sandbox can run in two ways, chosen depending on the hardware available.

- **On a single server.** CAPE runs in an isolated Docker container (the `internal: true` option plus INetSim, which fakes the internet), through the compose `sandbox` profile. This option requires a server able to expose nested virtualization to the container, which is not always straightforward to set up.
- **On two machines.** The orchestrator on one side, and a dedicated CAPE sandbox on the other, installed natively (no container). This is the recommended setup, and the one actually deployed for this project. It has two advantages: it avoids depending on nested virtualization on the main machine, and it physically isolates detonation, which after all means deliberately running potentially malicious code, on a separate machine.

Détail des deux options / Details on both options: [GUIDE-DEPLOIEMENT.md](GUIDE-DEPLOIEMENT.md#choisir-sa-topologie).

## 🧰 Stack technique / Tech stack

| Composant / Component | Rôle / Role |
| --- | --- |
| FastAPI (Python 3.11, async) | API orchestrateur / Orchestrator API |
| PostgreSQL 16 + SQLAlchemy 2.0 async | Stockage des verdicts + migrations Alembic / Verdict storage + Alembic migrations |
| Redis 7 | Cache des hash, rate limit, broker Celery / Hash cache, rate limit, Celery broker |
| Celery | Tâches longues (CAPE) / Long-running tasks (CAPE) |
| YARA (yara-python) | Détection par motifs / Pattern detection |
| ClamAV (clamd) | Signatures antivirus / Antivirus signatures |
| MISP | Threat intelligence |
| CAPE Sandbox v2 | Analyse comportementale dynamique / Dynamic behavioral analysis |
| Azure Identity + Microsoft Graph SDK | Auth en mode application sur le tenant M365 / App-only auth on the M365 tenant |
| APScheduler | Scans automatiques / Automatic scans |
| Prometheus + Grafana | Observabilité / Observability |
| Docker Compose v2 | Orchestration |

## 🚀 Démarrage rapide / Quick start

### 📋 Pré-requis / Requirements

- Ubuntu Server 22.04 ou 24.04 LTS (recommandé : 64 Go RAM, 32 cœurs, 2 To)
- Docker Engine 24.0 ou plus, avec Docker Compose v2
- Une application Azure AD avec les permissions Graph `Mail.Read` et `User.Read.All` (consentement administrateur)

### 📦 Installation

```bash
git clone https://github.com/f3n999/MailGuardianX.git mailguardianx
cd mailguardianx

# Génère tous les secrets Docker
chmod +x scripts/setup-secrets.sh
./scripts/setup-secrets.sh

# Remplir les 3 secrets Azure AD
nano secrets/azure_tenant_id.txt
nano secrets/azure_client_id.txt
nano secrets/azure_client_secret.txt

# Variables non secrètes
cp .env.example .env
nano .env   # activer SCHEDULE_ENABLED=true

# Démarrer la stack, sur un seul serveur (CAPE en conteneur) :
docker compose --profile sandbox up -d
# ou, en déploiement sur deux machines (recommandé, voir GUIDE-DEPLOIEMENT.md) :
#   définir CAPE_API_URL dans .env vers l'IP de la machine sandbox, puis :
# docker compose up -d

# Appliquer les migrations de base de données
docker compose exec orchestrator alembic upgrade head

# Créer la première clé API admin
curl -X POST http://localhost:8000/api/v1/admin/keys \
     -F "name=bootstrap" -F "scopes=analyze,upload,admin"
```

**FR.** Le guide complet ([GUIDE-DEPLOIEMENT.md](GUIDE-DEPLOIEMENT.md)) détaille tout : les deux topologies, l'installation pas à pas de la sandbox CAPE dédiée, et la récupération des tokens MISP et CAPE après le premier démarrage.

**EN.** The full guide ([GUIDE-DEPLOIEMENT.md](GUIDE-DEPLOIEMENT.md)) covers everything: both topologies, the step-by-step install of the dedicated CAPE sandbox, and how to retrieve the MISP and CAPE tokens after first boot.

## 📁 Structure du repo / Repo structure

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
│   │   ├── graph_ingestor.py    # Boucle scan tenant vers pipeline
│   │   └── scheduler.py         # APScheduler
│   ├── models/
│   │   ├── database.py          # Modèles SQLAlchemy (JSONB, indexes GIN)
│   │   └── schemas.py           # Schemas Pydantic (contrats API)
│   ├── services/
│   │   ├── auth.py              # Clés API bcrypt
│   │   ├── cache.py             # Redis
│   │   ├── cape_client.py       # CAPE Sandbox async
│   │   ├── clamav_client.py     # ClamAV via clamd
│   │   ├── misp_client.py       # MISP threat intel
│   │   ├── orchestrator.py      # Cerveau du pipeline
│   │   ├── stats.py             # Stats PostgreSQL pour le dashboard
│   │   └── yara_scanner.py      # YARA en mémoire
│   ├── tasks/cape_tasks.py      # Tâches Celery
│   └── tests/                   # Unitaires + intégration + E2E
├── alembic/                     # Migrations DB
├── yara-rules/                  # Règles YARA ransomware
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/                 # Datasources + dashboards JSON
├── scripts/
│   ├── init-db.sql              # Init PostgreSQL au premier démarrage
│   └── setup-secrets.sh         # Génération des Docker Secrets
├── secrets/                     # Fichiers de secrets (gitignored)
├── docker-compose.yml           # Stack complète
├── Dockerfile                   # Multi-stage (builder/base/prod/worker/dev)
├── requirements.txt
└── GUIDE-DEPLOIEMENT.md
```

## 🔌 L'API publique (extrait) / The public API (excerpt)

| Méthode / Method | Endpoint | Rôle / Role |
| --- | --- | --- |
| GET | `/` | Info service |
| GET | `/health` | État réel de chaque service (Redis, CAPE, MISP, ClamAV, YARA, scheduler) |
| GET | `/metrics` | Endpoint Prometheus |
| POST | `/api/v1/analyze` | Analyse metadata-only (auth requise) |
| POST | `/api/v1/upload` | Upload d'une pièce jointe vers YARA + ClamAV + CAPE (synchrone) |
| POST | `/api/v1/upload/async` | Idem en mode Celery (retourne `celery_task_id`) |
| GET | `/api/v1/verdict/{task_id}` | Verdict mis en cache par task_id |
| GET | `/api/v1/celery/{job_id}` | Statut ou résultat d'une tâche Celery |
| GET | `/api/v1/stats?window_hours=24` | Stats SOC (PostgreSQL) |
| GET | `/api/v1/sessions` | Historique des sessions de scan |
| POST | `/api/v1/scan/trigger` | Déclenche un scan Graph manuel |
| POST | `/api/v1/whitelist/{sha256}` | Met un hash en liste blanche |
| POST | `/api/v1/blacklist/{sha256}` | Met un hash en liste noire |
| POST | `/api/v1/admin/keys` | Crée une clé API (bcrypt) |
| GET | `/api/v1/admin/keys` | Liste les clés API actives |
| DELETE | `/api/v1/admin/keys/{id}` | Révoque une clé |

Documentation interactive / Interactive docs: `https://serveur:8000/docs` (Swagger UI).

## 🔐 Conformité RGPD et santé / GDPR and healthcare compliance

**FR.** La protection des données patient n'est pas une option ajoutée après coup, elle est au cœur de la conception. Voici comment chaque principe se traduit concrètement dans le code.

**EN.** Patient data protection is not an afterthought, it is at the core of the design. Here is how each principle translates concretely into the code.

| Principe / Principle | Implémentation / Implementation |
| --- | --- |
| Minimisation des données / Data minimization | Seuls le hash SHA256 et les métadonnées techniques sont transmis au backend |
| Pas de données patient / No patient data | Corps d'email, champs patients, noms : jamais transmis |
| Détection phishing locale / Local phishing detection | Sujet et aperçu du corps analysés en mémoire à l'ingestion, jamais conservés ; seuls un score 0-1 et des noms de catégorie sortent de cette étape |
| Chiffrement en transit / Encryption in transit | TLS partout (HTTPS, asyncpg SSL, mot de passe Redis) |
| Suppression après analyse / Deletion after analysis | Les fichiers envoyés à CAPE sont supprimés après le verdict (TTL configurable) |
| Restriction d'accès / Access control | Clés API bcrypt, scopes vérifiés, rate limiting par source |
| Traçabilité / Auditability | Tables `scan_sessions` et `email_analyses` en PostgreSQL, horodatées |
| Réseau isolé / Isolated network | CAPE n'a jamais accès au vrai Internet (INetSim simule les réponses) ; en déploiement deux machines, la détonation tourne sur une machine séparée |
| Secrets | Docker Secrets uniquement (pas de variables d'environnement sensibles, aucun fichier de secret committé) |

## 🧪 Tests

```bash
# Tests unitaires
pytest orchestrator/tests/unit -v

# Tests d'intégration (services mockés)
pytest orchestrator/tests/integration -v

# Tests de bout en bout sur l'API
pytest orchestrator/tests/e2e -v

# Tout lancer
pytest
```

## 🔒 Sécurité en production / Production security

**FR.** Avant de mettre MailGuardianX en production, voici les protections à mettre en place autour.

**EN.** Before putting MailGuardianX into production, here are the protections to set up around it.

- Reverse proxy HTTPS (Caddy ou Traefik) devant l'API
- Liste blanche d'IP sur `/api/v1/admin/*`
- Pare-feu UFW : seuls les ports 443 et 22 exposés
- SSH par clé uniquement (`PasswordAuthentication no`)
- Sauvegardes PostgreSQL automatisées
- Alertes Prometheus vers Slack ou Teams

Voir / See [GUIDE-DEPLOIEMENT.md](GUIDE-DEPLOIEMENT.md), section *Sécurité en production*.

## 👥 Équipe / Team

**Oteria Cyber School, promo B3 2025-2026**

Projet collectif / Team project : Matthieu, Mohammed, Michael, Thibault, Tess.

## 📄 Licence / License

[GNU General Public License v3.0](LICENSE)