# MailGuardianX — Sandbox CAPE

Documentation de la mise en place et configuration du sandbox d'analyse de malware CAPEv2 pour le projet MailGuardianX (Oteria B3).

## Architecture

```
Hôte (Ubuntu, 192.168.100.1)
│
├── KVM/QEMU — hyperviseur
│   └── VM cuckoo1 (Windows 10, 192.168.100.100)
│       └── agent.py (Python 3.10, port 8000) ← CAPE Agent v0.22
│
├── CAPEv2 (/opt/CAPEv2)
│   ├── cape.service       — moteur d'analyse
│   ├── cape-web.service   — interface web (port 8000 hôte)
│   └── cape-rooter.service — gestion réseau/iptables
│
├── virbr1 (192.168.100.0/24) — réseau isolé VM ↔ hôte
│   ├── Result server : 192.168.100.1:2042  ← capemon envoie les données ici
│   └── Agent HTTP :   192.168.100.100:8000 ← CAPE contrôle la VM ici
│
└── INetSim — simulation réseau (la VM n'a pas accès à Internet réel)
```

## Contraintes de sécurité

- La VM guest n'a **aucune route** vers Internet réel ni réseau de production
- Les fichiers analysés sont **supprimés après analyse** (conformité RGPD)
- L'API CAPE n'est accessible **que depuis 192.168.220.215**
- Aucun secret en clair dans ce dépôt — voir gestionnaire de secrets du projet

## Snapshot de référence

**Snapshot1** — état de référence de la VM avec agent.py en cours d'exécution.

Chaque analyse CAPE :
1. Revert la VM vers Snapshot1
2. Détecte l'agent (port 8000) en ~3 secondes
3. Upload `capemon_x64.dll` + `analyzer.py`
4. Exécute le sample sous surveillance
5. Envoie les données comportementales vers le result server (port 2042)
6. Génère un rapport JSON dans `/opt/CAPEv2/storage/analyses/<id>/`

### Recréer Snapshot1 (si nécessaire)

```bash
# 1. Démarrer la VM (sans snapshot)
virsh start cuckoo1

# 2. Lancer agent.py via wmiexec (voir setup/launch_agent_wmiexec.py)
#    Le hash NT du compte cape doit être dans la variable CAPE_VM_NT_HASH
CAPE_VM_NT_HASH=<hash> python3 setup/launch_agent_wmiexec.py

# 3. Prendre le snapshot avec agent en mémoire
virsh snapshot-create-as cuckoo1 Snapshot1 \
    --description "CAPE agent v0.22 running on port 8000" --atomic
```

## Problèmes résolus (session 2026-06-30 → 2026-07-01)

### 1. iptables bloquait le result server ← BUG CRITIQUE

**Symptôme** : toutes les analyses terminaient avec 0 processus, 0 signatures,
hard timeout 240s. Les répertoires `logs/`, `evtx/`, `CAPE/` n'existaient pas.

**Cause** : La chaîne `LIBVIRT_INP` n'autorisait que DNS(53) et DHCP(67) depuis
`virbr1`. Le trafic du guest vers `192.168.100.1:2042` était silencieusement DROP.

**Fix** :
```bash
sudo iptables -I INPUT 1 -i virbr1 -p tcp --dport 2042 -j ACCEPT \
    -m comment --comment "CAPE-resultserver"
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```
Voir aussi : `setup/iptables_fix.sh`

### 2. UAC token filtering bloquait wmiexec

**Cause** : `LocalAccountTokenFilterPolicy` absent → connexions admin à distance
filtrées (token sans privilèges).

**Fix** (appliqué offline via hivex sur SOFTWARE hive) :
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    LocalAccountTokenFilterPolicy = 1  (REG_DWORD)
```

### 3. CAPEAgent scheduled task corrompue

Un task scheduler `CAPEAgent` avec hash null causait de l'instabilité.
Supprimé offline via hivex (voir `scripts/offline-registry/remove_cape_task.py`).

### 4. freespace trop élevé

Le seuil `freespace = 50000` MB bloquait les analyses alors que le disque
n'a que ~48 GB libre. Abaissé à `40000` dans `/opt/CAPEv2/conf/cuckoo.conf`.

## Limites actuelles de la VM

| Limitation | Impact | Solution |
|------------|--------|----------|
| Pas de Microsoft Office | Fichiers .xlsx/.docx/etc. échouent | Installer LibreOffice ou MS Office + nouveau snapshot |
| Pas de Pillow (PIL) sur Python guest | Screenshots guest désactivés | `C:\Python310\python.exe -m pip install Pillow` + snapshot |
| UserManager crash au boot frais | Autologin ne fonctionne pas | Non bloquant (snapshot revert bypass ce problème) |
| luafv %%31 au boot frais | LUA File Virtualization fail | Non bloquant (même raison) |

## Structure du dossier

```
sandbox-cape/
├── README.md                          ← ce fichier
├── conf/
│   ├── kvm.conf                       ← configuration machine CAPE (cuckoo1)
│   └── cuckoo_changes.md              ← changements apportés à cuckoo.conf
├── scripts/
│   ├── start_agent_gp.bat             ← script GP Startup (dans la VM)
│   └── offline-registry/
│       ├── remove_cape_task.py        ← supprime CAPEAgent task corrompue
│       ├── fix_exectime.py            ← corrige ExecTime GP (REG_BINARY)
│       ├── write_bat2.py              ← écrit start_agent_gp.bat (CRLF)
│       ├── check_gp_keys.py           ← diagnostic clés registry GP
│       └── check_luafv.py             ← diagnostic luafv/UserManager
└── setup/
    ├── iptables_fix.sh                ← fix critique result server port 2042
    └── launch_agent_wmiexec.py        ← lance agent.py via PTH wmiexec
```

## Services CAPE

```bash
sudo systemctl status cape-rooter cape cape-web

# Logs en temps réel
sudo journalctl -u cape -f

# Vérifier iptables result server
sudo iptables -L INPUT -n | grep 2042
```

## Vérification rapide du pipeline

```bash
# 1. Agent répond ?
curl http://192.168.100.100:8000/

# 2. Snapshot existe ?
virsh snapshot-list cuckoo1

# 3. Result server écoute ?
ss -tlnp | grep 2042

# 4. Connexions actives pendant analyse ?
ss -tn | grep :2042
```
