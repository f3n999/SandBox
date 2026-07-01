#!/usr/bin/env python3
"""
Lance agent.py dans la VM Windows via impacket wmiexec + Pass-the-Hash.

Prérequis hôte :
    pip install impacket
    # VM cuckoo1 doit être démarrée (pas depuis snapshot)

Utilisation :
    python3 launch_agent_wmiexec.py

Ensuite prendre le snapshot :
    virsh snapshot-create-as cuckoo1 Snapshot1 \
        --description "CAPE agent v0.22 running on port 8000" --atomic

Note sécurité : le hash NT utilisé est celui du mot de passe vide (compte cape).
Ne pas stocker le hash en clair dans ce fichier en production.
Voir le gestionnaire de secrets du projet pour les credentials.
"""

import subprocess
import sys
import time

VM_IP = "192.168.100.100"
USERNAME = "cape"
# Hash NT du mot de passe vide — stocker dans un vault en prod, pas ici
NT_HASH_ENV = "CAPE_VM_NT_HASH"  # lire depuis variable d'environnement

AGENT_CMD = (
    r"C:\Python310\python.exe -c \""
    r"import subprocess,sys;"
    r"p=subprocess.Popen("
    r"[sys.executable,r'C:\\Users\\Public\\agent.py'],"
    r"creationflags=8"  # DETACHED_PROCESS
    r");"
    r"print(p.pid)"
    r"\""
)

def run_wmiexec(ip: str, user: str, nt_hash: str, cmd: str) -> str:
    """Exécute une commande via wmiexec PTH et retourne stdout."""
    proc = subprocess.run(
        [
            "python3", "-m", "impacket.examples.wmiexec",
            f"{user}@{ip}",
            "-hashes", f":{nt_hash}",
            cmd,
        ],
        capture_output=True, text=True, timeout=30,
    )
    return proc.stdout + proc.stderr


def verify_agent(ip: str, timeout: int = 15) -> bool:
    """Vérifie que l'agent répond sur port 8000."""
    import urllib.request, json
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://{ip}:8000/", timeout=2) as r:
                data = json.loads(r.read())
                if data.get("message") == "CAPE Agent!":
                    print(f"[+] Agent {data['version']} up — admin={data.get('is_user_admin')}")
                    return True
        except Exception:
            time.sleep(1)
    return False


if __name__ == "__main__":
    import os

    nt_hash = os.environ.get(NT_HASH_ENV)
    if not nt_hash:
        print(f"[!] Définir la variable d'environnement {NT_HASH_ENV}")
        sys.exit(1)

    print(f"[*] Lancement de agent.py sur {VM_IP}...")
    out = run_wmiexec(VM_IP, USERNAME, nt_hash, AGENT_CMD)
    print(f"[*] wmiexec output: {out.strip()}")

    if verify_agent(VM_IP):
        print("[+] Agent opérationnel. Prendre le snapshot :")
        print(f'    virsh snapshot-create-as cuckoo1 Snapshot1 \\')
        print(f'        --description "CAPE agent running on port 8000" --atomic')
    else:
        print("[!] Agent non joignable après lancement — vérifier la VM")
        sys.exit(1)
