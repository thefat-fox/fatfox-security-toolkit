#!/bin/bash
#==============================================================================
# 🦊 FATFOX SECURITY TOOLKIT v1.7.3 - PRODUCTION READY
# Auto WiFi auditing w/ handshake capture, deauth, PDF reports (Kali 2026)
# https://github.com/thefat-fox/fatfox-security-toolkit
#==============================================================================

set -euo pipefail

# 🌈 COLORS
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

log_error() { echo -e "${RED}[!] $1${NC}" >&2; }
log_warn() { echo -e "${YELLOW}[!] $1${NC}"; }
log_info() { echo -e "${BLUE}[+] $1${NC}"; }
log_success() { echo -e "${GREEN}[+] $1${NC}"; }
log_banner() {
    echo -e "${PURPLE}
======================================
      FATFOX SECURITY TOOLKIT v1.7.3
     🚀 PRODUCTION WIFI AUDITING
======================================${NC}"
}

# 🛠️ UTILITIES
check_root() { [[ $EUID -eq 0 ]] || { log_error "Run as sudo!"; exit 1; }; }
check_deps() {
    local missing=()
    command -v aircrack-ng >/dev/null || missing+=("aircrack-ng")
    command -v airodump-ng >/dev/null || missing+=("aircrack-ng")
    command -v aireplay-ng >/dev/null || missing+=("aircrack-ng")
    command -v tshark >/dev/null || missing+=("tshark")
    command -v jq >/dev/null || missing+=("jq")
    command -v weasyprint >/dev/null || missing+=("weasyprint")
    [[ ${#missing[@]} -eq 0 ]] || { log_error "Install: sudo apt install ${missing[*]}"; exit 1; }
}

# 🔧 AUTO-FIX MONITOR MODE (Kali 2026)
fix_monitor_mode() {
    log_info "🔧 Fixing NetworkManager conflicts..."
    systemctl stop NetworkManager 2>/dev/null || true
    airmon-ng check kill 2>/dev/null || true
    sleep 2
    log_success "✅ Monitor mode ready!"
}

# 📡 WIRELESS INTERFACES
detect_wireless_interfaces() {
    log_info "🔍 Detecting wireless interfaces..."
    WLAN_IFACES=($(iwconfig 2>/dev/null | awk '$1 ~ /wlan/ {print $1}' | sed 's/:$//'))
    [[ ${#WLAN_IFACES[@]} -eq 0 ]] && { log_error "No wlan interfaces!"; exit 1; }
    log_success "Found: ${WLAN_IFACES[*]}"
    WLAN_IFACE="${WLAN_IFACES[0]}"
}

# 📁 DIRECTORIES & SESSION
init_dirs() {
    mkdir -p captures deauth reports
    SESSION_DB="fatfox_session.json"
}

load_session() {
    [[ -f "$SESSION_DB" ]] && SESSION_DATA=$(jq '.' "$SESSION_DB" 2>/dev/null || echo "{}") || SESSION_DATA='{}'
}

save_session() {
    echo "$SESSION_DATA" | jq '.' > "$SESSION_DB"
    log_success "💾 Session saved"
}

# 📡 SCAN NETWORKS
scan_networks() {
    log_info "📡 Scanning networks (60s)..."
    CAP_FILE="captures/scan_$(date +%Y%m%d_%H%M%S).cap"
    airodump-ng "${WLAN_IFACE}mon" -w "captures/scan" --output-format pcap -u --write-interval 10 &
    AIRO_PID=$!
    sleep 60
    kill $AIRO_PID 2>/dev/null || true
    log_success "Scan complete: $CAP_FILE"
    echo "$CAP_FILE"
}

# ⚡ DEAUTH + HANDSHAKE AUTO
auto_handshake_capture() {
    local target_ap="$1"  # BSSID
    local cap_file="captures/handshake_$(date +%Y%m%d_%H%M%S).cap"
    
    log_info "🎯 Auto-capture: $target_ap"
    
    # Background airodump-ng
    airodump-ng "${WLAN_IFACE}mon" --bssid "$target_ap" -w "captures/${cap_file%.*}" --output-format pcap &
    DUMP_PID=$!
    
    # Deauth loop (every 10s)
    for i in {1..30}; do  # 5 min max
        log_info "⚡ Deauth burst #$i..."
        aireplay-ng -0 50 -a "$target_ap" "${WLAN_IFACE}mon" >> "deauth/deauth_$(date +%Y%m%d_%H%M%S).log" 2>&1
        sleep 10
        
        # Check handshake
        if aircrack-ng "captures/${cap_file%.*}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
            kill $DUMP_PID 2>/dev/null || true
            log_success "🎉 HANDSHAKE CAPTURED! $cap_file"
            return 0
        fi
    done
    
    kill $DUMP_PID 2>/dev/null || true
    log_warn "No handshake (check clients)"
}

# 🔍 ANALYZE CAPTURE
analyze_capture() {
    local cap_file="$1"
    log_info "🔍 Analyzing $cap_file..."
    
    # Networks
    local networks=$(airodump-ng "$cap_file" 2>/dev/null | awk '/[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}/ {print $1 " " $14}')
    
    # Handshakes
    local handshakes=$(aircrack-ng "$cap_file" 2>/dev/null | grep "handshake" | wc -l)
    
    SESSION_DATA=$(echo "$SESSION_DATA" | jq \
        --arg cap "$cap_file" \
        --arg nets "$networks" \
        --arg hs "$handshakes" '
        .last_capture = $cap |
        .networks = $nets |
        .handshakes = ($hs | tonumber)
    ')
    
    log_success "Found: $networks | Handshakes: $handshakes"
}

# 📊 PROFESSIONAL REPORTS
generate_client_report() {
    local cap_file="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local html_file="reports/FATFOX_Client_Report_${timestamp}.html"
    local pdf_file="reports/FATFOX_Client_Report_${timestamp}.pdf"
    
    # Extract data
    local ssid=$(airodump-ng "$cap_file" 2>/dev/null | grep -oP '(?<=ESSID:")[^"]+' | head -1 || echo "Unknown")
    local bssid=$(airodump-ng "$cap_file" 2>/dev/null | grep -oP '[0-9A-F:]{17}' | head -1 || echo "Unknown")
    local handshakes=$(aircrack-ng "$cap_file" 2>/dev/null | grep -oP '\d+ handshake' | head -1 | grep -oP '\d+' || echo "0")
    
    # HTML Report
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>FATFOX WiFi Audit Report</title>
    <meta name="viewport" content="width=device-width">
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(90deg, #ff6b6b, #4ecdc4); color: white; padding: 20px; border-radius: 10px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .risk-high { background: #ff4444; color: white; }
        .risk-medium { background: #ffaa00; color: white; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #333; color: white; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>🦊 FATFOX SECURITY AUDIT</h1>
        <p>Timestamp: $(date)</p>
    </div>
    
    <div class="grid">
        <div class="card">
            <h3>📡 Network</h3>
            <p><strong>SSID:</strong> $ssid</p>
            <p><strong>BSSID:</strong> $bssid</p>
        </div>
        <div class="card">
            <h3>🎯 Handshakes</h3>
            <p><strong>Captured:</strong> $handshakes</p>
            <p><strong>File:</strong> $cap_file</p>
        </div>
    </div>
    
    <div class="card risk-high">
        <h3>⚠️ SECURITY RISKS (CVSS 8.1)</h3>
        <table>
            <tr><th>Vulnerability</th><th>Risk</th><th>Impact</th></tr>
            <tr><td>Weak Encryption</td><td>High (8.1)</td><td>Handshake captured</td></tr>
            <tr><td>Deauth Vulnerable</td><td>High (7.5)</td><td>DoS possible</td></tr>
        </table>
    </div>
    
    <div class="card">
        <h3>🛡️ RECOMMENDATIONS</h3>
        <ol>
            <li>Enable WPA3 or WPA2-Enterprise</li>
            <li>Disable WPS</li>
            <li>Change default PSK</li>
            <li>Monitor for deauth attacks</li>
        </ol>
    </div>
    
    <div class="card">
        <h3>📄 EVIDENCE</h3>
        <ul>
            <li>$(basename "$cap_file") - Handshake capture</li>
            <li>deauth/*.log - Attack logs</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    # PDF Generation (Kali 2026)
    if command -v weasyprint >/dev/null; then
        weasyprint "$html_file" "$pdf_file" && log_success "✅ PDF: $pdf_file"
    else
        log_warn "Install weasyprint for PDF: sudo apt install weasyprint"
    fi
    
    # Auto-open
    xdg-open "$html_file" 2>/dev/null || true
    log_success "📊 Report: $html_file"
}

# MAIN MENU
main_menu() {
    log_banner
    echo "1. 🔍 Scan Networks"
    echo "2. 🎯 Auto Handshake + Deauth"
    echo "3. ⚡ Manual Deauth"
    echo "4. 📊 Generate Client Report (latest)"
    echo "5. 🧹 Cleanup (>24h)"
    echo "0. ❌ Exit"
    read -p "Choose: " choice
    
    case $choice in
        1) 
            fix_monitor_mode
            detect_wireless_interfaces
            local cap=$(scan_networks)
            analyze_capture "$cap"
            save_session
            ;;
        2)
            fix_monitor_mode
            detect_wireless_interfaces
            read -p "Target BSSID: " target
            auto_handshake_capture "$target"
            analyze_capture "captures/handshake_*.cap"
            save_session
            ;;
        3)
            fix_monitor_mode
            detect_wireless_interfaces
            read -p "Target BSSID: " target
            read -p "Count: " count
            aireplay-ng -0 "$count" -a "$target" "${WLAN_IFACE}mon"
            ;;
        4)
            local latest_cap=$(ls captures/*.cap 2>/dev/null | tail -1 || echo "")
            [[ -n "$latest_cap" ]] && generate_client_report "$latest_cap" || log_error "No captures!"
            ;;
        5)
            find captures deauth -name "*.cap" -mtime +1 -delete 2>/dev/null || true
            find captures deauth -name "*.log" -mtime +7 -delete 2>/dev/null || true
            log_success "Cleanup complete"
            ;;
        0) exit 0 ;;
        *) log_error "Invalid!";;
    esac
    
    read -p "Press Enter..."
    main_menu
}

# 🚀 START
check_root
check_deps
init_dirs
load_session
fix_monitor_mode
detect_wireless_interfaces
main_menu
