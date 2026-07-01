# Modifications apportées à cuckoo.conf

Fichier original : `/opt/CAPEv2/conf/cuckoo.conf`

## Changements effectués

| Clé | Valeur par défaut | Valeur actuelle | Raison |
|-----|-------------------|-----------------|--------|
| `freespace` | 50000 | **40000** | Disque hôte a ~48 GB libre, le seuil 50 GB bloquait les analyses |
| `machinery` | kvm | kvm | inchangé |
| `ip` (resultserver) | 192.168.100.1 | 192.168.100.1 | IP virbr1 de l'hôte |
| `port` (resultserver) | 2042 | 2042 | Port capemon → result server |

## Section [resultserver]

```ini
[resultserver]
ip = 192.168.100.1
port = 2042
force_port = yes
```

## Attention

Le `freespace` peut être remonté si de l'espace disque est libéré.
Commande pour vérifier : `df -h /`
