#!/bin/bash
# Fix critique : autoriser le guest CAPE à joindre le result server (port 2042)
#
# PROBLÈME : LIBVIRT_INP n'autorise que DNS(53) et DHCP(67) depuis virbr1.
# Le capemon.dll du guest tente de se connecter à 192.168.100.1:2042 pour
# envoyer les données de comportement. Sans cette règle → DROP → zéro behavior.
#
# SYMPTÔME : toutes les analyses se terminent avec 0 processus, 0 signatures,
# hard timeout 240s, répertoires logs/ evtx/ CAPE/ absents dans les analyses.
#
# À exécuter une fois au démarrage (ou après reboot).

set -e

COMMENT="CAPE-resultserver"
INTERFACE="virbr1"
PORT="2042"

# Vérifier si la règle existe déjà
if sudo iptables -L INPUT -n | grep -q "$COMMENT"; then
    echo "[OK] Règle iptables déjà présente pour port $PORT"
else
    sudo iptables -I INPUT 1 -i "$INTERFACE" -p tcp --dport "$PORT" \
        -j ACCEPT -m comment --comment "$COMMENT"
    echo "[+] Règle iptables ajoutée : virbr1 → port $PORT ACCEPT"
fi

# Persistance
sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
echo "[+] Règles sauvegardées dans /etc/iptables/rules.v4"

# Vérification
echo ""
echo "Règles actives concernant le port 2042 :"
sudo iptables -L INPUT -n --line-numbers | grep -E "2042|$COMMENT"
