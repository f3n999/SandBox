# Journal de débogage — Mise en place du sandbox CAPE

Session : 2026-06-30 / 2026-07-01 (9h+ de travail)
Objectif : agent.py démarrant automatiquement sur la VM + CAPE pipeline fonctionnel

## Chronologie des problèmes et solutions

### Phase 1 — Autologin cassé (non bloquant in fine)

**Problème** : UserManager (ID 7024) crashe avec %%0 à chaque boot frais depuis 19h13.
Corrélation : luafv échoue avec %%31 quelques secondes avant.

**Investigations** :
- Vérifié `LimitBlankPasswordUse = 0` dans SYSTEM hive ✓ (pas le problème)
- Vérifié que `cape` est dans le groupe Administrators via chntpw ✓
- Supprimé CAPEAgent TaskCache corrompue → n'a pas résolu UserManager
- Examiné logs EVTX offline via python-evtx

**Conclusion** : Probablement corruption NTFS des drivers depuis virsh destroy répétés.
**Non bloquant** : le snapshot revert bypasse complètement le boot frais.

### Phase 2 — SMB auth failure

**Problème** : `smbclient -N` → `NT_STATUS_LOGON_FAILURE`

**Cause** : Le flag `-N` envoie une session NULL, pas NTLM avec mdp vide.

**Solution** : Pass-the-Hash avec le hash NT du mot de passe vide.
Hash utilisé stocké en variable d'environnement, pas dans ce fichier.

### Phase 3 — wmiexec access denied

**Problème** : `rpc_s_access_denied` même avec auth valide.

**Cause** : UAC token filtering pour comptes locaux en remote.
`LocalAccountTokenFilterPolicy` absent = token filtré = pas de droits admin.

**Solution** : Ajout offline via hivex sur SOFTWARE hive :
```
HKLM\...\Policies\System\LocalAccountTokenFilterPolicy = 1
```

### Phase 4 — GP script NTFS write issue

**Problème** : Le script GP startup se lance (confirmé par ID 5018) mais n'écrit
rien sur disque. Ni `echo >`, ni `python.exe open()` ne persistent.

**Cause root** : Contexte Session 0 SYSTEM en GP — les writes NTFS échouent
silencieusement. Les écritures registry (`reg add`) aussi.

**Workaround** : Non nécessaire — la solution snapshot remet ça obsolète.

### Phase 5 — agent.py lancé avec succès

**Méthode finale** :
```python
# Via impacket wmiexec avec PTH
cmd = (
    r'C:\Python310\python.exe -c "'
    r'import subprocess,sys;'
    r'p=subprocess.Popen([sys.executable,r"C:\\Users\\Public\\agent.py"],'
    r'creationflags=8);'  # DETACHED_PROCESS
    r'print(p.pid)"'
)
```

PID obtenu : 2024. Port 8000 ouvert immédiatement.
`{"message": "CAPE Agent!", "version": "0.22", "is_user_admin": true}`

### Phase 6 — Snapshot1 créé

```bash
sudo virsh snapshot-create-as cuckoo1 Snapshot1 \
    --description "CAPE agent v0.22 running on port 8000" --atomic
```

Test : revert → port 8000 opérationnel en 3 secondes.

### Phase 7 — Zero behavior capture (iptables)

**Problème** : Toutes les analyses : 0 processus, 0 signatures, hard timeout 240s.
Les répertoires `logs/`, `evtx/` n'existaient pas dans les analyses.

**Investigation** :
- Result server écoute bien sur 192.168.100.1:2042 ✓
- Aucune connexion ESTAB vers :2042 pendant les analyses ← problème
- `LIBVIRT_INP` : seulement DNS(53) et DHCP(67) autorisés depuis virbr1
- Les règles CAPE-rooter dans INPUT ciblent 192.168.100.100 (la VM), pas l'hôte
  → inefficaces pour le trafic VM→hôte

**Fix** :
```bash
sudo iptables -I INPUT 1 -i virbr1 -p tcp --dport 2042 -j ACCEPT \
    -m comment --comment "CAPE-resultserver"
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

**Vérification post-fix** : `ss -tn | grep :2042` montre ESTAB pendant l'analyse.
`analysis.log` reçu depuis le guest, répertoires créés correctement.

## État final

- Snapshot1 fonctionnel ✓
- Pipeline CAPE end-to-end opérationnel ✓
- Behavior capture activée ✓
- freespace abaissé à 40 GB ✓
- Règle iptables persistante (/etc/iptables/rules.v4) ✓

## Ce qui reste à faire (optionnel)

1. Installer LibreOffice/MS Office dans la VM pour analyser les documents Office
2. Installer Pillow sur Python guest pour activer les screenshots
3. Investiguer le crash UserManager/luafv au boot frais (low priority)
