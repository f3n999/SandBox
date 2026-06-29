# MailGuardianX — Guide de déploiement

Déployer la solution complète sur un serveur Ubuntu (recommandé : 64 Go RAM / 32 cœurs / 2 To).

---

## Choisir sa topologie

Deux façons de déployer, selon ce que l'infrastructure permet :

| | Topologie A — un serveur | Topologie B — deux machines |
|---|---|---|
| **Quand** | Hôte avec virtualisation imbriquée disponible (VT-x/AMD-V exposé) | Hôte sans virtualisation imbriquée, ou besoin d'isoler la détonation sur sa propre machine |
| **CAPE** | Conteneur Docker (`docker compose --profile sandbox up -d`) | Installation native sur une deuxième machine, voir [Topologie B](#topologie-b--deux-machines) |
| **Effort** | Une commande | Deux machines à provisionner, CAPE installé à la main |

La topologie B est celle qui a été déployée et démontrée pour ce projet : l'hyperviseur utilisé (ESXi) n'exposait pas la virtualisation imbriquée par défaut, et séparer la détonation — qui exécute volontairement du code potentiellement malveillant — sur sa propre machine est de toute façon la pratique la plus sûre, indépendamment de cette contrainte technique.

Les étapes 1 à 9 ci-dessous couvrent la machine orchestrateur, commune aux deux topologies. La section Topologie B détaille ensuite la deuxième machine.

---

## Pré-requis

- Ubuntu Server 22.04 ou 24.04 LTS
- Docker Engine ≥ 24.0
- Docker Compose v2 (`docker compose`)
- `openssl` et `acl` (`apt install acl`, pour les permissions des secrets Grafana)
- Une application Azure AD (mode app-only) — voir section "Azure AD"
- Topologie B uniquement : une deuxième machine Ubuntu avec virtualisation imbriquée exposée (VT-x/AMD-V), voir [Topologie B](#topologie-b--deux-machines)

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

Topologie A (un serveur, CAPE en conteneur) :

```bash
docker compose --profile sandbox up -d
```

Topologie B (deux machines — voir [section dédiée](#topologie-b--deux-machines) pour la deuxième machine) :

```bash
docker compose up -d
```

Sans `--profile sandbox`, les services `cape`, `mongodb` et `inetsim` ne démarrent pas sur cette machine — c'est voulu, ils tournent sur la machine sandbox. Penser à renseigner `CAPE_API_URL` dans `.env` avec l'IP de cette deuxième machine avant de lancer cette commande.

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

Topologie A (CAPE en conteneur sur cette même machine) :

```bash
docker compose exec cape cat /opt/CAPEv2/conf/api.conf | grep token
```

Topologie B (CAPE natif sur la machine sandbox) :

```bash
ssh <utilisateur>@<ip-machine-sandbox> "sudo cat /opt/CAPEv2/conf/api.conf" | grep token
```

Dans les deux cas : coller la valeur dans `secrets/cape_api_token.txt` sur la machine orchestrateur. Si `token_auth_enabled = no` (valeur par défaut documentée en Topologie B), ce champ n'a pas besoin d'être un vrai token — l'accès à l'API CAPE est alors contrôlé par le pare-feu plutôt que par un secret applicatif ; laisser la valeur par défaut suffit.

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

## Topologie B — deux machines

Cette section couvre la deuxième machine : une sandbox de détonation CAPE dédiée, séparée de l'orchestrateur. C'est la configuration qui a été déployée et démontrée pour ce projet.

### Pourquoi une machine à part

L'orchestrateur (FastAPI, PostgreSQL, Redis, ClamAV, MISP, Grafana) n'a aucune raison d'être en contact avec du code potentiellement malveillant. La sandbox, elle, fait exactement ça : exécuter un fichier suspect dans une VM Windows jetable pour observer son comportement. Si quelque chose dérape — une évasion de sandbox, un bug dans l'outil d'analyse, un ransomware qui tente de se propager — la compromission reste confinée à cette machine.

Il y a aussi une contrainte technique : CAPE fait tourner des VM Windows à l'intérieur de cette machine Linux, ce qui demande de la virtualisation imbriquée. C'est rarement activé par défaut sur un hyperviseur (ESXi, Proxmox, VirtualBox...), et certains environnements cloud ne le proposent pas du tout. Mieux vaut une machine dédiée, configurée une fois pour ça, que de fragiliser l'orchestrateur avec cette exigence.

### Pré-requis de cette machine

- Ubuntu Server 22.04 ou 24.04 LTS, 8 vCPU / 16 Go RAM / 100 Go disque au minimum
- Virtualisation imbriquée exposée par l'hyperviseur — à vérifier en premier, avant toute installation :

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo
```

Si la commande renvoie `0`, il n'existe aucun contournement logiciel : l'hyperviseur doit d'abord exposer VT-x ou AMD-V à cette VM. Sur ESXi, ça se fait dans les paramètres de la VM, section CPU, en cochant l'option qui expose la virtualisation matérielle assistée au système d'exploitation invité — la VM doit être éteinte puis redémarrée pour que le changement prenne effet. Sur Proxmox, passer le type de CPU à `host`. Sur VirtualBox, `VBoxManage modifyvm <nom> --nested-hw-virt on`. Si rien de tout ça n'est possible, la seule option fiable reste une machine physique avec VT-x/VT-d activé au BIOS.

### 1. KVM, QEMU, libvirt

```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients \
  bridge-utils virtinst virt-manager libvirt-dev
sudo usermod -aG libvirt,kvm "$USER"
kvm-ok   # doit confirmer que /dev/kvm est utilisable
```

`libvirt-dev` est nécessaire pour que CAPE puisse compiler son module Python `libvirt-python` à l'étape suivante — l'installer dès maintenant évite un échec silencieux plus tard.

### 2. MongoDB

MongoDB stocke les rapports d'analyse de CAPE : des documents JSON complexes et de taille variable, exactement le cas d'usage d'une base orientée documents plutôt que relationnelle.

Vérifier l'instruction CPU AVX avant d'installer quoi que ce soit :

```bash
cat /proc/cpuinfo | grep flags | grep avx
```

MongoDB 5.0 et 6.0 exigent AVX. Sur une VM dont l'hyperviseur présente un profil CPU de référence au niveau du cluster plutôt que les capacités réelles du processeur physique, AVX peut être absent même si VT-x est bien exposé — c'est arrivé lors du déploiement de ce projet, alors ne pas supposer que l'un implique l'autre.

**Si AVX est présent**, installer la branche 7.0 (cohérente avec l'image `mongo:7` utilisée côté topologie A) :

```bash
curl -fsSL https://pgp.mongodb.com/server-7.0.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg
echo "deb [signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update && sudo apt install -y mongodb-org
```

**Si AVX est absent**, installer MongoDB 4.4, la dernière branche qui n'en a pas besoin. Deux complications s'ajoutent : 4.4 n'a jamais été packagée pour Ubuntu 22.04 (utiliser le dépôt qui cible Ubuntu 20.04, compatible au niveau binaire), et elle dépend de `libssl1.1`, qu'Ubuntu 22.04 a remplacée par `libssl3`.

```bash
# libssl1.1 — récupérer le paquet le plus récent dans les archives Ubuntu 20.04
# (vérifier la version disponible sur http://security.ubuntu.com/ubuntu/pool/main/o/openssl/)
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.23_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.23_amd64.deb

# Dépôt MongoDB 4.4, packages ciblant Ubuntu 20.04 (focal)
wget -qO- https://www.mongodb.org/static/pgp/server-4.4.asc | sudo gpg --dearmor -o /usr/share/keyrings/mongodb-server-4.4.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/mongodb-server-4.4.gpg] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
sudo apt update && sudo apt install -y mongodb-org
```

### 3. CAPEv2

```bash
git clone https://github.com/kevoreilly/CAPEv2.git /opt/CAPEv2
cd /opt/CAPEv2/installer
sudo bash cape2.sh base       # crée l'utilisateur système "cape", dépendances système
sudo bash cape2.sh sandbox    # dépendances Python (environnement poetry), signatures
sudo bash cape2.sh systemd    # services cape, cape-processor, cape-web, cape-rooter
```

L'installation native — pas un conteneur — est volontaire ici : CAPE doit piloter KVM directement depuis l'hôte, et un conteneur qui doit lui-même accéder à `/dev/kvm` et à l'API libvirt du noyau ajoute des problèmes de permissions et de stabilité plutôt que de les résoudre. L'utilisateur dédié `cape`, plutôt que root, limite les dégâts si un échantillon particulièrement retors arrivait à compromettre l'outil d'analyse lui-même.

PostgreSQL est aussi installé par `cape2.sh base` et héberge la file de tâches CAPE (statuts, métadonnées des échantillons) — une base distincte de celle de l'orchestrateur, propre à cette machine.

### 4. Réseau d'analyse isolé

```bash
sudo virsh net-define /dev/stdin <<'EOF'
<network>
  <name>analysis</name>
  <bridge name="virbr1"/>
  <forward mode="nat"/>
  <ip address="192.168.100.1" netmask="255.255.255.0">
    <dhcp><range start="192.168.100.100" end="192.168.100.200"/></dhcp>
  </ip>
</network>
EOF
sudo virsh net-start analysis
sudo virsh net-autostart analysis
```

Puis bloquer explicitement toute route entre ce réseau et l'interface physique, et rediriger le trafic applicatif vers INetSim (adapter `ens160` au nom réel de l'interface physique) :

```bash
sudo iptables -A FORWARD -i virbr1 -o ens160 -j DROP
sudo iptables -t nat -A PREROUTING -i virbr1 -p udp --dport 53  -j DNAT --to 192.168.100.1
sudo iptables -t nat -A PREROUTING -i virbr1 -p tcp --dport 80  -j DNAT --to 192.168.100.1
sudo iptables -t nat -A PREROUTING -i virbr1 -p tcp --dport 443 -j DNAT --to 192.168.100.1
```

C'est la règle de sécurité centrale de toute la sandbox : si un ransomware réel s'exécute dans la VM Windows, il ne doit jamais pouvoir contacter un vrai serveur de commande et contrôle, ni atteindre un autre réseau. INetSim répond à sa place — faux DNS, faux HTTP — pour lui donner l'illusion d'être connecté.

Les deux règles travaillent ensemble, pas en double emploi : le DNAT intercepte DNS/HTTP/HTTPS même si le malware ignore la configuration réseau de la VM et tente de joindre un résolveur DNS public codé en dur — ce que font beaucoup d'échantillons réels. Le DROP en FORWARD est le filet de sécurité pour tout le reste (autre port, autre protocole) qui tenterait malgré tout de sortir vers le réseau physique.

Penser à persister ces règles iptables (`iptables-persistent`, ou un script rechargé via `rc.local`) pour qu'elles survivent à un redémarrage.

### 5. INetSim

```bash
wget -qO- http://www.inetsim.org/inetsim-archive-signing-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/inetsim.gpg
echo "deb [signed-by=/usr/share/keyrings/inetsim.gpg] http://www.inetsim.org/debian/ binary/" | sudo tee /etc/apt/sources.list.d/inetsim.list
sudo apt update && sudo apt install -y inetsim
```

Dans `/etc/inetsim/inetsim.conf`, fixer `service_bind_address` et `dns_default_ip` sur `192.168.100.1` — INetSim ne doit écouter que sur le réseau d'analyse, jamais sur l'interface physique.

### 6. Configuration de CAPE

| Fichier | Paramètres |
|---|---|
| `conf/kvm.conf` | `interface = virbr1`, `ip = 192.168.100.100` (IP de la VM Windows), `snapshot = Snapshot1`, `arch = x64`, `tags = win10` |
| `conf/cuckoo.conf` | `ip = 192.168.100.1` (adresse à laquelle la VM Windows renvoie ses journaux d'analyse) ; connexion PostgreSQL locale |
| `conf/api.conf` | `token_auth_enabled = no` — la sécurité de cette API repose sur le pare-feu (étape suivante), pas sur un token applicatif. C'est un choix pragmatique pour ce contexte ; à reconsidérer si la sandbox doit un jour accepter des clients autres que l'orchestrateur. |

### 7. Pare-feu

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow from <ip-machine-orchestrateur> to any port 8000 proto tcp
sudo ufw enable
```

Seule la machine orchestrateur doit pouvoir atteindre l'API CAPE. N'importe quelle autre source se voit refuser la connexion avant même que la requête HTTP ne soit examinée.

### 8. VM Windows invitée

C'est la seule étape qui reste manuelle : installer un système Windows demande de parcourir un assistant graphique, et ça ne se scripte pas raisonnablement sans des outils de déploiement dédiés (MDT, WDS, Packer) qui n'apportent rien pour une seule VM destinée à une démonstration. On le fait une fois, à la main, puis on fige l'état avec un snapshot que CAPE restaurera avant chaque analyse future.

1. Récupérer l'ISO Windows 10 Enterprise Evaluation (gratuite, 90 jours, Microsoft Evaluation Center) et la déposer dans `/var/lib/libvirt/images/win10.iso`.
2. `sudo bash /opt/CAPEv2/utils/create-win10-vm.sh` — crée un disque de 60 Go, attache l'ISO, connecte la VM au réseau `analysis` et démarre l'installation.
3. Se connecter par VNC via un tunnel SSH : `ssh -L 5900:127.0.0.1:5900 <utilisateur>@<ip-machine-sandbox>`, puis ouvrir un client VNC sur `localhost:5900`.
4. Installer Windows normalement.
5. Configurer le réseau en statique dans Windows : IP `192.168.100.100`, masque `255.255.255.0`, passerelle et DNS `192.168.100.1`.
6. Désactiver Windows Defender, les mises à jour automatiques, le pare-feu Windows, l'UAC, la veille et le verrouillage de session — ces désactivations laissent le malware s'exécuter sans être bloqué avant que CAPE ait pu observer son comportement, et permettent à CAPE de restaurer la VM proprement après chaque analyse.
7. Installer Python (64 bits), copier `agent.py` depuis `/opt/CAPEv2/agent/`, et le configurer en démarrage automatique (planificateur de tâches Windows, déclencheur "à l'ouverture de session").
8. Installer Microsoft Office, pour pouvoir détoner les pièces jointes `.docm` et `.xlsm` — le vecteur principal ciblé par MailGuardianX.
9. Éteindre proprement la VM, puis figer le snapshot :

```bash
sudo virsh snapshot-create-as cuckoo1 Snapshot1 "Clean baseline for CAPE"
sudo virsh snapshot-list cuckoo1
```

### 9. Vérification

```bash
curl -s -F "file=@eicar.com" http://127.0.0.1:8000/apiv2/tasks/create/file/
```

Une réponse avec un `task_id` confirme que l'API répond. `GET /apiv2/tasks/view/<id>/` doit ensuite passer de `pending` à `running` puis `reported` une fois le snapshot en place — sans snapshot, `cape.service` reste en boucle de redémarrage en attendant une VM qui n'existe pas encore, ce qui est normal tant que l'étape précédente n'est pas terminée.

### Problèmes connus sur cette machine

| Symptôme | Cause | Solution |
|---|---|---|
| `mongod` plante au démarrage, signal `ILL` | MongoDB 5.0+/6.0 exige AVX, absent sur cette VM | Installer MongoDB 4.4 (voir étape 2) |
| `cape.service` : `ModuleNotFoundError: No module named 'libvirt'` | `libvirt-dev` installé après la tentative de compilation du module Python | `apt install libvirt-dev` puis `poetry run pip install libvirt-python==<version installée>` dans l'environnement de l'utilisateur `cape` |
| `psycopg2.errors.DuplicateTable: relation "tags" already exists` | Le script d'installation a tourné plusieurs fois et a tenté de recréer un schéma déjà présent | `DROP DATABASE cape; CREATE DATABASE cape OWNER cape;` puis relancer `cape.service` |
| `cape.service` reste en boucle de redémarrage | La VM `cuckoo1` n'existe pas encore (ou le snapshot n'a pas été pris) | Terminer l'étape 8 |

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
| Grafana en boucle de redémarrage, log `permission denied` sur un secret | Les fichiers de secrets sont des bind mounts qui gardent leurs permissions hôte (chmod 600), et Grafana tourne sous un autre utilisateur (uid 472). Réexécuter `scripts/setup-secrets.sh` (il applique désormais l'ACL nécessaire), ou manuellement : `setfacl -m u:472:r secrets/postgres_password.txt secrets/grafana_password.txt` |

---

## Sécurité — production

- [ ] Reverse proxy (Caddy / Traefik) devant l'API avec HTTPS Let's Encrypt
- [ ] IP allowlist sur `/api/v1/admin/*` au niveau du reverse proxy
- [ ] Firewall UFW : seulement 443 (HTTPS) et 22 (SSH) exposés
- [ ] SSH par clé uniquement (`PasswordAuthentication no`)
- [ ] Backups PostgreSQL automatisés (cron quotidien)
- [ ] Alertes Prometheus → Slack/Teams sur les pannes services
