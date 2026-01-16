#  GUIDE COMPLET : CAPE V2 Pour Défense Anti-Ransomware

##  Table des matières

1. [Introduction & Concepts](#introduction)
2. [Architecture CAPE](#architecture)
3. [Installation Complète](#installation)
4. [Configuration](#configuration)
5. [Utilisation Pratique](#utilisation)
6. [Intégration avec Orchestrateur](#intégration)
7. [YARA Signatures](#yara)
8. [Troubleshooting](#troubleshooting)
9. [Cas d'Usage Ransomware](#casusage)
10. [Optimisations Performance](#optimisations)

---

##  Introduction & Concepts

### Qu'est-ce que CAPE V2 ?

**CAPE** = **Config And Payload Extraction**

C'est un **sandbox malware** sophistiqué qui :
- ✅ **Exécute** des fichiers malveillants de manière isolée
- ✅ **Enregistre** toutes les actions (API calls, réseau, fichiers, registre)
- ✅ **Capture** les payloads non-packés (shellcode injecté, DLL, etc.)
- ✅ **Extrait** automatiquement les configurations de malware
- ✅ **Utilise un debugger** pour contourner les anti-sandbox
- ✅ **Genère des rapports** JSON détaillés

### Pourquoi CAPE pour le ransomware ?

| Aspect | Valeur pour toi |
|--------|-----------------|
| **Détection zero-day** | Comportement + signatures YARA |
| **Unpacking automatique** | Révèle payloads cachés |
| **Configuration extraction** | Récupère clés C2, URLs de payment |
| **Anti-evasion** | Contourne virtualisation detection |
| **API Hooking** | Enregistre appels système suspects |
| **Memory dumps** | Analyse complète du ransomware |

---

##  Architecture CAPE

### Composants clés

```
┌─────────────────────────────────────────────────────┐
│         CAPE Server (Ubuntu/Debian)                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐ │
│  │   API      │  │   Web UI   │  │   Database   │ │
│  │ (analyse)  │  │(dashboard) │  │ (PostgreSQL) │ │
│  └────────────┘  └────────────┘  └──────────────┘ │
│                      │                              │
│                      ▼                              │
│              ┌─────────────────┐                   │
│              │    Rooter       │                   │
│              │(orchestration)  │                   │
│              └────────┬────────┘                   │
│                       │                            │
└───────────────────────┼────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
    ┌────────┐     ┌────────┐     ┌────────┐
    │ VM Win │     │ VM Win │     │ VM Win │
    │ (10)   │     │ (10)   │     │ (10)   │
    │ agent  │     │ agent  │     │ agent  │
    └────────┘     └────────┘     └────────┘
    (Snapshot)    (Snapshot)    (Snapshot)
```

---

##  Installation Complète

### Prérequis matériel

 Recommandé pour 3 VM:
- CPU: 8+ cores (Intel VT-x ou AMD-V)
- RAM: 32GB+ (16GB par VM)
- Disque: 500GB+ SSD
- Réseau: 1Gbps

### Étape 1 : Préparation Host (Ubuntu 24.04)

```bash
# Mise à jour système
sudo apt-get update && sudo apt-get upgrade -y

# Installation dépendances critiques
sudo apt-get install -y git python3-pip python3-venv libffi-dev libssl-dev postgresql redis-server qemu-kvm libvirt-daemon-system libvirt-clients virt-manager tcpdump volatility3

# KVM setup
sudo usermod -aG libvirt $(whoami)
sudo usermod -aG kvm $(whoami)
sudo systemctl enable libvirtd

# PostgreSQL setup
sudo -u postgres psql -c "CREATE USER cape WITH PASSWORD 'CapeSecurePass123!'"
sudo -u postgres psql -c "CREATE DATABASE cape OWNER cape"
```

### Étape 2 : Cloner et configurer CAPE

```bash
# Clone CAPE
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2

# Python venv
python3 -m venv venv
source venv/bin/activate

# Dépendances
pip install -r requirements.txt

# Configurations
cp conf/cape.conf.default conf/cape.conf
cp conf/routing.conf.default conf/routing.conf

# Database
python3 manage.py migrate
python3 manage.py createsuperuser
```

---

##  Configuration clés

### cape.conf - Configuration maître

```ini
[database]
connection = postgresql://cape:CapeSecurePass123!@localhost:5432/cape

[timeouts]
default = 120
maximum = 300

[kvm]
machines = windows10-cape
memory = 4096

[processing]
enable_yara = yes
extract_config = yes
```

---

##  Utilisation Pratique

### API REST - Soumettre une analyse

```python
import requests
import asyncio

CAPE_URL = "http://localhost:8000"

async def submit_file(file_path):
    with open(file_path, 'rb') as f:
        files = {'file': f}
        data = {
            'timeout': 120,
            'priority': 3,
            'tags': 'ransomware'
        }
        response = requests.post(
            f"{CAPE_URL}/apiv2/tasks/create/file",
            files=files,
            data=data
        )
    return response.json()['task_id']

async def get_verdict(task_id):
    response = requests.get(
        f"{CAPE_URL}/apiv2/tasks/get/report/{task_id}",
        params={'type': 'json'}
    )
    report = response.json()['report']
    
    return {
        'verdict': 'malware' if report.get('signatures') else 'clean',
        'signatures': [s['name'] for s in report.get('signatures', [])],
        'confidence': len(report.get('signatures', [])) * 0.2
    }
```

---

##  Intégration Orchestrateur

### CAPE Client pour ton API

```python
# orchestrator/core/cape_client.py

import httpx
from typing import Dict, Optional

class CAPEClient:
    def __init__(self, cape_url: str = "http://cape:8000", timeout: int = 300):
        self.cape_url = cape_url
        self.timeout = timeout
    
    async def submit_file(
        self,
        file_path: str,
        file_data: bytes,
        priority: int = 3,
        timeout: int = 120
    ) -> Dict:
        """Soumet un fichier à CAPE pour analyse."""
        try:
            files = {'file': file_data}
            data = {
                'timeout': timeout,
                'priority': priority,
                'options': 'unpacker=2',
                'tags': 'ransomware,auto-detection'
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.cape_url}/apiv2/tasks/create/file",
                    files=files,
                    data=data
                )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'task_id': result.get('task_id'),
                    'status': 'submitted'
                }
            else:
                return {
                    'task_id': None,
                    'status': 'error',
                    'message': f"CAPE error: {response.text}"
                }
        
        except Exception as e:
            return {
                'task_id': None,
                'status': 'error',
                'message': f"Exception: {str(e)}"
            }
    
    async def get_report(self, task_id: int) -> Optional[Dict]:
        """Récupère le rapport d'analyse."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.cape_url}/apiv2/tasks/get/report/{task_id}",
                    params={'type': 'json'}
                )
            
            if response.status_code == 200:
                return response.json()
            return None
        
        except Exception as e:
            print(f"Error getting report: {e}")
            return None
    
    async def get_verdict(self, task_id: int) -> Dict:
        """Génère un verdict à partir du rapport."""
        report = await self.get_report(task_id)
        
        if not report:
            return {
                'verdict': 'unknown',
                'confidence': 0.0,
                'signatures': []
            }
        
        report_data = report.get('report', {})
        signatures = report_data.get('signatures', [])
        
        ransomware_score = len(signatures) * 0.2
        
        verdict = 'malware' if ransomware_score >= 0.6 else ('suspicious' if ransomware_score >= 0.3 else 'clean')
        
        return {
            'verdict': verdict,
            'confidence': min(ransomware_score, 1.0),
            'signatures': [s.get('name') for s in signatures],
            'task_id': task_id
        }
    
    async def wait_for_completion(self, task_id: int, max_wait: int = 600) -> bool:
        """Attend que l'analyse soit complète."""
        import asyncio
        elapsed = 0
        while elapsed < max_wait:
            report = await self.get_report(task_id)
            if report:
                return True
            
            await asyncio.sleep(10)
            elapsed += 10
        
        return False


# Utilisation dans Orchestrateur
async def analyze_with_cape(file_data: bytes) -> Dict:
    cape = CAPEClient()
    
    # Soumettre
    submit_result = await cape.submit_file(
        file_path="suspect.exe",
        file_data=file_data,
        timeout=120
    )
    
    if submit_result['status'] != 'submitted':
        return {'verdict': 'error', 'message': submit_result.get('message')}
    
    task_id = submit_result['task_id']
    
    # Attendre
    if await cape.wait_for_completion(task_id):
        # Verdict
        verdict = await cape.get_verdict(task_id)
        return verdict
    
    return {'verdict': 'timeout', 'message': 'CAPE analysis took too long'}
```

---

##  YARA Signatures

### Ransomware Behavior Signatures

```yara
rule Ransomware_CryptoAPI {
    meta:
        description = "Ransomware using CryptoAPI"
        author = "Oteria B3"
        severity = "critical"
    
    strings:
        $crypt1 = "CryptEncrypt"
        $crypt2 = "CryptDecrypt"
        $crypt3 = "CryptGenKey"
        $file1 = "CreateFileW"
        $file2 = "WriteFile"
        $msg1 = "your files are encrypted" nocase
    
    condition:
        (any of ($crypt*)) and (any of ($file*)) and (any of ($msg*))
}

rule Ransomware_LockBit_Behavior {
    meta:
        description = "LockBit ransomware specific behavior"
    
    strings:
        $lockbit = "LockBit" nocase
        $ransom_note = "Restore-My-Files.txt"
    
    condition:
        any of them
}

rule Ransomware_ProcessInjection {
    meta:
        description = "Process injection typical of ransomware"
    
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
    
    condition:
        all of them
}
```

---

## 🔧 Troubleshooting

### "No machines available"

```bash
# Vérifier VMs
sudo virsh list --all

# Vérifier snapshots
sudo virsh snapshot-list windows10-cape

# Redémarrer rooter
systemctl restart cape-rooter
sudo journalctl -u cape-rooter -f
```

### "Agent timeout"

```bash
# Vérifier agent dans VM (RDP)
cd C:\CAPE
python agent.py

# Vérifier réseau
ping -c 1 192.168.1.50

# Augmenter timeout dans conf/cape.conf
# [timeouts]
# maximum = 300
```

### "Database connection error"

```bash
sudo systemctl status postgresql
sudo -u postgres psql -c "\l"
sudo systemctl restart postgresql
```

---

##  Optimisations Performance

### 1. Parallel Analysis

```ini
[kvm]
machines = windows10-1,windows10-2,windows10-3,windows10-4
```

### 2. Fast Bypass

```python
SAFE_EXTENSIONS = ['.pdf', '.txt', '.doc', '.jpg']

async def quick_check(file_data: bytes, filename: str):
    """Quick verdict sans CAPE"""
    if filename.endswith(tuple(SAFE_EXTENSIONS)):
        return 'clean'
    return None  # Nécessite CAPE
```

---

##  Checklist Déploiement

- [ ] Host Ubuntu 24.04 configuré
- [ ] KVM/QEMU installé et testé
- [ ] PostgreSQL et MongoDB lancés
- [ ] CAPE clôné et dépendances installées
- [ ] VM Windows 10 créée avec snapshot
- [ ] Agent CAPE fonctionnel
- [ ] API accessible (http://localhost:8000)
- [ ] Web UI accessible (http://localhost:8080)
- [ ] YARA rules compilées
- [ ] Client Python testé
- [ ] Orchestrateur connecté à CAPE

---
