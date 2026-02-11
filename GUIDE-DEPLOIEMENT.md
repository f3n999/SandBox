# 📖 Guide de Déploiement & Utilisation

Guide complet pour déployer la stack anti-ransomware, de la machine physique au premier verdict.

---

## Table des matières

1. [Prérequis matériel](#1-prérequis-matériel)
2. [Prérequis logiciel](#2-prérequis-logiciel)
3. [Installation pas à pas](#3-installation-pas-à-pas)
4. [Configuration](#4-configuration)
5. [Lancement](#5-lancement)
6. [Configuration CAPE Sandbox](#6-configuration-cape-sandbox)
7. [Configuration MISP](#7-configuration-misp)
8. [Test du système](#8-test-du-système)
9. [Déploiement de l'agent](#9-déploiement-de-lagent)
10. [Monitoring & Dashboard](#10-monitoring--dashboard)
11. [Maintenance](#11-maintenance)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prérequis matériel

### Machine Backend (héberge toute la stack)

Il vous faut **une seule machine physique ou VM puissante** côté prestataire.
CAPE Sandbox tourne des VM Windows à l'intérieur, donc il faut de la ressource.

#### Configuration minimale (POC / démo)

| Ressource | Minimum | Détail |
|-----------|---------|--------|
| **CPU** | 4 cores | Intel VT-x ou AMD-V **obligatoire** (virtualisation imbriquée pour CAPE) |
| **RAM** | 16 GB | 4 GB pour les services + 8 GB pour 1 VM CAPE + 4 GB OS |
| **Disque** | 200 GB SSD | SSD obligatoire (les HDD sont trop lents pour CAPE) |
| **Réseau** | 100 Mbps | Suffisant pour un POC |
| **OS** | Ubuntu 24.04 LTS | Ou Debian 12 |

#### Configuration recommandée (production — 3 VM CAPE en parallèle)

| Ressource | Recommandé | Détail |
|-----------|------------|--------|
| **CPU** | 8–16 cores | Intel VT-x/AMD-V, idéalement Xeon ou Ryzen Pro |
| **RAM** | 32–64 GB | 4 GB services + 3×8 GB VM CAPE + 8 GB OS/buffer |
| **Disque** | 500 GB – 1 TB NVMe SSD | Les rapports CAPE + MongoDB prennent de la place |
| **Réseau** | 1 Gbps | Pour recevoir les fichiers des agents |
| **OS** | Ubuntu 24.04 LTS Server | |

#### Configuration idéale (multi-hôpitaux)

| Ressource | Idéal | Détail |
|-----------|-------|--------|
| **CPU** | 32 cores | Analyse parallèle de 6+ fichiers simultanés |
| **RAM** | 128 GB | 6 VM CAPE + services + buffer confortable |
| **Disque** | 2 TB NVMe RAID 1 | Redondance + performance |
| **Réseau** | 10 Gbps | Multi-sites |
| **OS** | Ubuntu 24.04 LTS Server | |

> **Point critique** : la virtualisation matérielle (VT-x / AMD-V) doit être activée dans le BIOS.
> Sans ça, CAPE ne peut pas lancer de VM Windows → pas d'analyse dynamique.
> Si vous utilisez un VPS cloud, vérifiez que le provider supporte la nested virtualization
> (OVH bare metal, Hetzner dedicated, AWS bare metal — PAS les VPS classiques).

### Postes Hôpital (agents)

Aucune exigence particulière. L'agent est léger :

| Ressource | Minimum |
|-----------|---------|
| **OS** | Windows 10/11 |
| **RAM** | 50 MB utilisés par l'agent |
| **Disque** | 20 MB installé |
| **Réseau** | Accès HTTPS vers le backend |

---

## 2. Prérequis logiciel

Sur la machine backend, installer :

```bash
# Mise à jour système
sudo apt update && sudo apt upgrade -y

# Docker (version 24+)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Docker Compose (version 2.20+, intégré à Docker maintenant)
docker compose version
# Si absent :
sudo apt install docker-compose-plugin

# KVM/QEMU (nécessaire pour CAPE)
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients virt-manager
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER
sudo systemctl enable libvirtd

# Git
sudo apt install -y git curl

# Vérifier la virtualisation matérielle
egrep -c '(vmx|svm)' /proc/cpuinfo
# Si le résultat est 0 → VT-x/AMD-V n'est PAS activé → BIOS à configurer
```

**Redémarrer la session** après les `usermod` :
```bash
newgrp docker
newgrp libvirt
```

---

## 3. Installation pas à pas

### 3.1. Cloner le dépôt

```bash
git clone https://github.com/VOTRE-ORG/ransomware-defense.git
cd ransomware-defense
```

### 3.2. Configurer les secrets

```bash
# Copier le template
cp .env.example .env

# Générer des vrais secrets
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
# Copier le résultat dans SECRET_KEY du .env

# Éditer le .env avec VOS mots de passe
nano .env
```

**Règles absolues pour le `.env` :**
- Aucun mot de passe par défaut (`admin`, `password`, `SecurePass123` → NON)
- Minimum 16 caractères par mot de passe
- Chaque service a son propre mot de passe
- Le fichier `.env` ne doit **JAMAIS** être commité (il est dans le `.gitignore`)

Voici ce que vous devez remplir :

```bash
# .env — exemple de valeurs (CHANGEZ TOUT)

SECRET_KEY=votre_secret_64_chars_genere_avec_python
DATABASE_URL=postgresql://orchestrator_user:MotDePasseComplexe1!@postgres:5432/orchestrator_db

CAPE_API_TOKEN=genere-apres-install-cape
CAPE_DB_PASSWORD=CapeDbPass_Unique_2025!

MISP_API_KEY=genere-apres-install-misp
MISP_ADMIN_EMAIL=admin@votre-domaine.local
MISP_ADMIN_PASSPHRASE=MispAdmin_Complexe_2025!
MYSQL_MISP_PASSWORD=MispMysql_Unique_2025!

POSTGRES_USER=postgres
POSTGRES_PASSWORD=PostgresAdmin_Complexe_2025!
MYSQL_ROOT_PASSWORD=MysqlRoot_Complexe_2025!

REDIS_PASSWORD=RedisPass_Complexe_2025!

GRAFANA_USER=admin
GRAFANA_PASSWORD=GrafanaAdmin_2025!

LOG_LEVEL=INFO
```

### 3.3. Initialiser la base de données

Éditez `scripts/init-db.sql` pour y mettre les mêmes mots de passe que dans votre `.env` :

```bash
nano scripts/init-db.sql
```

```sql
CREATE DATABASE orchestrator_db;
CREATE DATABASE cape_db;

CREATE USER orchestrator_user WITH PASSWORD 'MotDePasseComplexe1!';
GRANT ALL PRIVILEGES ON DATABASE orchestrator_db TO orchestrator_user;

CREATE USER cape_user WITH PASSWORD 'CapeDbPass_Unique_2025!';
GRANT ALL PRIVILEGES ON DATABASE cape_db TO cape_user;
```

---

## 4. Configuration

### 4.1. Ports utilisés

Vérifiez qu'aucun de ces ports n'est déjà occupé :

| Port | Service | Accès |
|------|---------|-------|
| `8000` | Orchestrateur API | Agents + Dashboard |
| `8080` | CAPE Web UI / API | Admin uniquement |
| `8081` | MISP HTTP | Admin uniquement |
| `8443` | MISP HTTPS | Admin uniquement |
| `5432` | PostgreSQL | Interne Docker uniquement |
| `3306` | MySQL | Interne Docker uniquement |
| `6379` | Redis | Interne Docker uniquement |
| `27017` | MongoDB | Interne Docker uniquement |
| `3000` | Grafana | Dashboard SOC |
| `9090` | Prometheus | Métriques |

```bash
# Vérifier les ports libres
sudo ss -tlnp | grep -E '(8000|8080|8081|8443|5432|3306|6379|27017|3000|9090)'
```

### 4.2. Firewall

Côté backend, ouvrir uniquement :

```bash
# UFW (Ubuntu)
sudo ufw allow 8000/tcp   # API Orchestrateur (accès agents)
sudo ufw allow 3000/tcp   # Grafana (accès SOC)
sudo ufw allow 22/tcp     # SSH admin
sudo ufw enable

# Les autres ports restent internes (Docker network)
```

**Ne PAS exposer** les ports 8080 (CAPE), 8443 (MISP), 5432 (Postgres), 6379 (Redis) sur Internet.

---

## 5. Lancement

### 5.1. Démarrer la stack

```bash
cd ransomware-defense

# Premier lancement (build + pull images)
docker compose up -d --build

# Vérifier que tout tourne
docker compose ps
```

Résultat attendu :

```
NAME              STATUS              PORTS
orchestrator      Up (healthy)        0.0.0.0:8000->8000/tcp
cape-sandbox      Up                  0.0.0.0:8080->8000/tcp
misp              Up                  0.0.0.0:8081->80/tcp, 0.0.0.0:8443->443/tcp
postgres          Up (healthy)        5432/tcp
mysql             Up (healthy)        3306/tcp
mongodb           Up                  27017/tcp
redis             Up (healthy)        6379/tcp
grafana           Up                  0.0.0.0:3000->3000/tcp
prometheus        Up                  0.0.0.0:9090->9090/tcp
```

### 5.2. Vérifier le health check

```bash
curl http://localhost:8000/health
```

Réponse attendue :
```json
{
  "status": "healthy",
  "timestamp": "2025-02-11T10:00:00.000000",
  "services": {
    "api": "up",
    "redis": "up",
    "cape": "up",
    "misp": "up"
  }
}
```

Si un service est `"down"`, voir la section [Troubleshooting](#12-troubleshooting).

### 5.3. Accéder à la documentation API

Ouvrir dans le navigateur : **http://VOTRE-IP:8000/docs**

Swagger UI avec tous les endpoints, schémas, et possibilité de tester directement.

---

## 6. Configuration CAPE Sandbox

CAPE est le composant le plus complexe. Il nécessite une **VM Windows** à l'intérieur du serveur.

### 6.1. Créer la VM Windows pour CAPE

```bash
# Télécharger une ISO Windows 10 (évaluation Microsoft, gratuit 90 jours)
# https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise

# Créer la VM avec virt-manager (interface graphique)
virt-manager
# Ou en ligne de commande :
sudo virt-install \
  --name windows10-cape \
  --ram 4096 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/win10-cape.qcow2,size=60 \
  --os-variant win10 \
  --network bridge=virbr0 \
  --graphics vnc \
  --cdrom /chemin/vers/Win10_Eval.iso
```

### 6.2. Configurer la VM Windows

Une fois Windows installé dans la VM :

1. **Désactiver Windows Defender** (sinon il supprime les samples)
2. **Désactiver Windows Update**
3. **Désactiver le pare-feu Windows**
4. **Installer Python 3.8+** dans la VM
5. **Copier l'agent CAPE** :

```powershell
# Dans la VM Windows
mkdir C:\CAPE
# Copier agent.py depuis le repo CAPE
# https://github.com/kevoreilly/CAPEv2/blob/master/agent/agent.py
python C:\CAPE\agent.py
```

6. **Configurer le réseau** : IP statique dans le même réseau que le host
7. **Créer un snapshot** (état de départ pour chaque analyse) :

```bash
# Sur le host Linux
sudo virsh snapshot-create-as windows10-cape clean_snapshot \
  --description "Clean state for CAPE analysis"
```

### 6.3. Configurer CAPE

Dans le conteneur CAPE, éditer la configuration :

```bash
docker exec -it cape-sandbox bash

# Fichier de config des machines
nano /opt/CAPEv2/conf/kvm.conf
```

```ini
[kvm]
machines = windows10-cape

[windows10-cape]
label = windows10-cape
platform = windows
ip = 192.168.122.10      # IP de la VM Windows
snapshot = clean_snapshot
interface = virbr0
resultserver_ip = 192.168.122.1   # IP du host sur le bridge
resultserver_port = 2042
tags = windows10,x64
```

### 6.4. Récupérer le token API CAPE

```bash
# Dans le conteneur CAPE
docker exec -it cape-sandbox python3 /opt/CAPEv2/manage.py createapitoken
# Copier le token → mettre dans .env (CAPE_API_TOKEN)
```

---

## 7. Configuration MISP

### 7.1. Premier accès

```bash
# Attendre que MISP soit prêt (peut prendre 2-3 minutes)
docker logs misp -f

# Accéder à l'interface : https://VOTRE-IP:8443
# Login par défaut : l'email et passphrase définis dans .env
```

### 7.2. Récupérer la clé API

1. Se connecter à MISP Web UI
2. Aller dans **Administration** → **Auth Keys** → **Add authentication key**
3. Copier la clé → mettre dans `.env` (`MISP_API_KEY`)

### 7.3. Ajouter des feeds de threat intelligence

Dans MISP Web UI : **Sync Actions** → **Feeds** → **Load default feed metadata**

Feeds recommandés pour ransomware :

- **CIRCL OSINT Feed** — IOCs généraux
- **Botvrij.eu** — Indicateurs malware
- **Abuse.ch URLhaus** — URLs malveillantes
- **Abuse.ch MalwareBazaar** — Hash de malware

```bash
# Activer le fetch automatique des feeds
docker exec -it misp /var/www/MISP/app/Console/cake Server fetchFeed 1 all
```

---

## 8. Test du système

### 8.1. Test rapide — hash connu

```bash
# Envoyer une requête de test au backend
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: votre-cle-api-32-chars-minimum-ici" \
  -H "X-Agent-ID: test-agent-01" \
  -d '{
    "agent_id": "test-agent-01",
    "hospital_id": "hopital-test",
    "email": {
      "message_id": "<test-001@example.com>",
      "sender": "collegue@hopital-paris.fr",
      "sender_domain": "hopital-paris.fr",
      "recipient_count": 1,
      "subject_hash": "'"$(echo -n 'Test sujet' | sha256sum | cut -d' ' -f1)"'",
      "received_at": "2025-02-11T10:00:00Z",
      "has_attachments": true,
      "spf_result": "pass",
      "dkim_result": "pass",
      "dmarc_result": "pass"
    },
    "attachments": [
      {
        "filename": "rapport-mensuel.pdf",
        "file_size": 245000,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_type": "pdf",
        "is_encrypted": false,
        "is_macro_enabled": false
      }
    ]
  }'
```

Réponse attendue :
```json
{
  "task_id": "uuid-genere",
  "overall_verdict": "allow",
  "stage": "verdict_ready",
  "requires_file_upload": false,
  "analysis_time_ms": 15,
  "message": "Email autorisé — aucune menace détectée"
}
```

### 8.2. Test — pièce jointe suspecte

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: votre-cle-api-32-chars-minimum-ici" \
  -H "X-Agent-ID: test-agent-01" \
  -d '{
    "agent_id": "test-agent-01",
    "hospital_id": "hopital-test",
    "email": {
      "message_id": "<test-002@example.com>",
      "sender": "invoice-payment@fake-ameli.fr",
      "sender_domain": "fake-ameli.fr",
      "recipient_count": 85,
      "subject_hash": "'"$(echo -n 'URGENT facture impayée' | sha256sum | cut -d' ' -f1)"'",
      "received_at": "2025-02-11T10:05:00Z",
      "has_attachments": true,
      "spf_result": "fail",
      "dkim_result": "fail",
      "dmarc_result": "fail"
    },
    "attachments": [
      {
        "filename": "facture.pdf.exe",
        "file_size": 12000,
        "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "file_type": "exe",
        "is_encrypted": true,
        "is_macro_enabled": false,
        "mime_type": "application/pdf"
      }
    ]
  }'
```

Réponse attendue :
```json
{
  "task_id": "uuid-genere",
  "overall_verdict": "block",
  "stage": "verdict_ready",
  "requires_file_upload": false,
  "analysis_time_ms": 8,
  "message": "Email bloqué — menace détectée",
  "attachments": [
    {
      "sha256": "deadbeef...",
      "verdict": "block",
      "confidence": 0.92,
      "threat_name": "Heuristic/HighRisk",
      "signatures_matched": [
        "high_risk_ext:exe=0.95",
        "double_extension",
        "encrypted_archive",
        "mime_type_mismatch",
        "suspicious_size:0.15",
        "multiple_auth_failures",
        "suspicious_sender:invoice-payment",
        "health_domain_spoofing:ameli.fr",
        "mass_recipients:85"
      ],
      "analysis_source": "heuristic"
    }
  ]
}
```

Ce test démontre que **l'heuristique seule** bloque cette attaque en < 10ms, sans même passer par MISP ou CAPE. C'est la force du pipeline en cascade.

### 8.3. Test CAPE (si configuré)

```bash
# Blacklist pour tester
curl -X POST "http://localhost:8000/api/v1/blacklist/aaaa$(python3 -c 'print("a"*60)')" \
  -H "X-API-Key: votre-cle-api-32-chars-minimum-ici"

# Whitelist pour faux positif
curl -X POST "http://localhost:8000/api/v1/whitelist/bbbb$(python3 -c 'print("b"*60)')" \
  -H "X-API-Key: votre-cle-api-32-chars-minimum-ici"
```

---

## 9. Déploiement de l'agent

### 9.1. Spécification de l'agent

L'agent est un programme léger installé sur chaque poste Windows de l'hôpital.

**Ce qu'il fait :**
- Surveille l'arrivée de nouveaux emails (via Outlook COM / MAPI)
- Extrait les métadonnées et calcule le SHA256 des pièces jointes
- Envoie ces infos au backend (HTTPS)
- Applique le verdict reçu (ALLOW / BLOCK / QUARANTINE)

**Ce qu'il ne fait PAS :**
- Lire le contenu des emails
- Accéder aux données patient
- Envoyer quoi que ce soit sans chiffrement

### 9.2. Déploiement type

```
Serveur Active Directory de l'hôpital
  └── GPO de déploiement
        └── MSI / script d'installation de l'agent
              └── Config : URL backend + clé API
```

L'agent se configure avec un fichier `agent.conf` :

```ini
[backend]
url = https://votre-backend.example.com:8000
api_key = votre-cle-api-agent

[agent]
id = hopital-paris-poste-042
hospital_id = hopital-paris

[policy]
deep_analysis_enabled = true
max_file_upload_size = 50000000
```

---

## 10. Monitoring & Dashboard

### 10.1. Grafana

Accès : **http://VOTRE-IP:3000**

Login avec les identifiants définis dans `.env`.

Dashboards à configurer :
- Nombre d'emails analysés / heure
- Ratio ALLOW vs BLOCK
- Temps de réponse moyen du pipeline
- Top 10 des domaines bloqués
- Alertes sur pics de détection

### 10.2. Prometheus

Accès : **http://VOTRE-IP:9090**

Métriques exposées par l'orchestrateur via `/metrics`.

### 10.3. Logs

```bash
# Logs de l'orchestrateur
docker compose logs orchestrator -f --tail 100

# Logs CAPE
docker compose logs cape-sandbox -f --tail 50

# Logs de tous les services
docker compose logs -f
```

---

## 11. Maintenance

### 11.1. Mises à jour

```bash
cd ransomware-defense
git pull origin main

# Rebuild et redéployer
docker compose down
docker compose up -d --build
```

### 11.2. Backups

```bash
# Backup PostgreSQL
docker exec postgres pg_dumpall -U postgres > backup_$(date +%Y%m%d).sql

# Backup volumes Docker
docker run --rm -v ransomware-defense_postgres-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/postgres-data-$(date +%Y%m%d).tar.gz /data
```

### 11.3. Rotation des logs

```bash
# Configurer la rotation Docker
sudo nano /etc/docker/daemon.json
```

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  }
}
```

### 11.4. Mise à jour des règles YARA

```bash
# Éditer les règles
nano yara-rules/ransomware_detection.yar

# Recharger dans CAPE (les règles sont montées en volume)
docker compose restart cape-sandbox
```

---

## 12. Troubleshooting

### "Redis connection refused"

```bash
docker compose logs redis
docker compose restart redis

# Vérifier que Redis tourne
docker exec redis redis-cli ping
# Doit répondre "PONG"
```

### "CAPE: No machines available"

```bash
# Vérifier que KVM fonctionne
sudo virsh list --all

# La VM doit être à l'état "shut off" avec un snapshot
sudo virsh snapshot-list windows10-cape

# Redémarrer CAPE
docker compose restart cape-sandbox
```

### "MISP 502 Bad Gateway"

MISP est lent au démarrage (2–5 minutes). Attendre et réessayer.

```bash
docker compose logs misp -f
# Attendre "MISP is ready"
```

### "Orchestrator unhealthy"

```bash
# Vérifier les logs
docker compose logs orchestrator --tail 50

# Causes fréquentes :
# 1. .env mal configuré (mot de passe incorrect)
# 2. PostgreSQL pas encore prêt (depends_on ne suffit pas toujours)
# 3. Redis pas accessible

# Redémarrer dans l'ordre
docker compose restart postgres redis
sleep 10
docker compose restart orchestrator
```

### "Port already in use"

```bash
# Identifier ce qui occupe le port
sudo ss -tlnp | grep :8000
# Ou
sudo lsof -i :8000

# Tuer le processus ou changer le port dans .env
ORCHESTRATOR_PORT=8001
```

### Performance lente

```bash
# Vérifier les ressources
docker stats

# Si un conteneur utilise trop de RAM
docker compose down
# Ajuster les limites dans docker-compose.yml :
# deploy:
#   resources:
#     limits:
#       memory: 4G
```

---

## Résumé des accès

| Service | URL | Usage |
|---------|-----|-------|
| API Orchestrateur | `http://IP:8000` | Agents + tests |
| Swagger Docs | `http://IP:8000/docs` | Documentation interactive |
| CAPE Web UI | `http://IP:8080` | Admin — analyses manuelles |
| MISP | `https://IP:8443` | Admin — threat intelligence |
| Grafana | `http://IP:3000` | Dashboard SOC |
| Prometheus | `http://IP:9090` | Métriques brutes |

---
