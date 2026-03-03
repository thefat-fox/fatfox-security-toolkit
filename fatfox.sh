#!/bin/bash

# ======================================
# FATFOX SECURITY TOOLKIT v1.4.1
# Smart Monitor Detection Upgrade
# ======================================

CAPTURE_DIR="$HOME/fatfox-wifi/captures"
mkdir -p "$CAPTURE_DIR"

clear
echo "======================================"
echo "     FATFOX SECURITY TOOLKIT v1.4.1"
echo "     Authorized WiFi Audit Only"
echo "======================================"
echo ""

# ------------------------------
# Authorization Check
# ------------------------------

read -p "Confirm written authorization? (yes/no): " AUTH

if [[ "$AUTH" != "y" ]]; then
    echo "[✘] Authorization required. Exiting."
    exit 1
fi

echo "[+] Authorization confirmed."
echo ""

# ------------------------------
# Kill Interfering Services (Optional)
# ------------------------------

if systemctl is-active --quiet NetworkManager; then
    echo "[!] NetworkManager is running."
    read -p "Kill interfering processes automatically? (yes/no): " KILLNM

    if [[ "$KILLNM" == "y" ]]; then
        sudo airmon-ng check kill > /dev/null 2>&1
        echo "[+] Interfering processes killed."
    else
        echo "[!] Proceeding without killing NetworkManager."
    fi
else
    echo "[+] NetworkManager not interfering."
fi

echo ""

# ------------------------------
# Smart Monitor Interface Detection
# ------------------------------

echo "[*] Detecting monitor mode interfaces..."

ALL_IFACES=($(iw dev | awk '$1=="Interface"{print $2}'))
VALID_MON=()

for IFACE in "${ALL_IFACES[@]}"; do
    MODE=$(iw dev "$IFACE" info 2>/dev/null | grep type | awk '{print $2}')
    if [[ "$MODE" == "monitor" ]]; then
        VALID_MON+=("$IFACE")
    fi
done

if [ ${#VALID_MON[@]} -eq 0 ]; then
    echo "[✘] No monitor interface detected."
    echo "[!] Enable monitor mode first, example:"
    echo "    sudo airmon-ng start wlan1"
    exit 1
fi

if [ ${#VALID_MON[@]} -eq 1 ]; then
    INTERFACE="${VALID_MON[0]}"
    echo "[+] Automatically selected: $INTERFACE"
else
    echo "[+] Multiple monitor interfaces found:"
    select INTERFACE in "${VALID_MON[@]}"; do
        [[ -n "$INTERFACE" ]] && break
    done
fi

echo ""

# ------------------------------
# Interface Health Check
# ------------------------------

check_interface_status() {
    IFACE="$1"

    STATE=$(ip link show "$IFACE" | grep -o "state [A-Z]*" | awk '{print $2}')

    if [ "$STATE" != "UP" ]; then
        echo "[!] Interface $IFACE is DOWN."
        echo "[*] Attempting to bring it UP..."
        sudo ip link set "$IFACE" up
        sleep 2

        STATE2=$(ip link show "$IFACE" | grep -o "state [A-Z]*" | awk '{print $2}')

        if [ "$STATE2" = "UP" ]; then
            echo "[+] Interface successfully brought UP."
        else
            echo "[✘] Failed to bring interface UP."
            echo "[!] Possible driver issue."
        fi
    else
        echo "[+] Interface $IFACE is UP."
    fi
}

check_interface_status "$INTERFACE"
echo ""

# ------------------------------
# Target Input
# ------------------------------

read -p "Enter target SSID: " SSID
read -p "Enter target BSSID: " BSSID
read -p "Enter channel: " CHANNEL

echo ""
echo "Target Summary:"
echo "SSID: $SSID"
echo "BSSID: $BSSID"
echo "Channel: $CHANNEL"
echo ""

read -p "Proceed with capture? (yes/no): " CONFIRM
[[ "$CONFIRM" != "yes" ]] && exit 0

# ------------------------------
# Start Capture (Resilient Mode)
# ------------------------------

SESSION_NAME="${SSID}_$(date +%Y%m%d_%H%M%S)"
CAPTURE_FILE="$CAPTURE_DIR/$SESSION_NAME"

echo ""
echo "[*] Starting session: $SESSION_NAME"
echo ""

start_capture() {

    while true; do

        check_interface_status "$INTERFACE"

        airodump-ng -c "$CHANNEL" --bssid "$BSSID" -w "$CAPTURE_FILE" "$INTERFACE"

        echo ""
        echo "[!] Capture stopped unexpectedly."
        echo "[*] Checking interface state..."

        check_interface_status "$INTERFACE"

        read -p "Restart capture? (yes/no): " RETRY
        [[ "$RETRY" != "yes" ]] && break
    done
}

start_capture

echo ""
echo "[+] Session ended."
echo "[+] Capture saved to:"
echo "    $CAPTURE_FILE-01.cap"
echo ""
echo "🦊 FatFox v1.4.1 complete."
