#!/bin/bash
# /usr/local/bin/ddos-guard.sh
# DDoS Guard - Automatic SYN flood detection and mitigation

set -euo pipefail

# Default configuration
CONFIG_FILE="/etc/ddos-guard/ddos-guard.conf"
WHITELIST_FILE="/etc/ddos-guard/whitelist.txt"
LOG_FILE="/var/log/ddos-guard.log"
STATE_FILE="/var/run/ddos-guard.state"
LOCK_FILE="/var/run/ddos-guard.lock"

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # Source the config file
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    else
        # Use defaults
        THRESHOLD=10
        CHECK_INTERVAL=30
        SUBNET_MASK=24
        PORTS="443"
        ENABLE_IPV4=true
        ENABLE_IPV6=false
        AUTO_UNBLOCK_HOURS=0  # 0 = never auto-unblock
        SAVE_IPTABLES=true
    fi
    
    # Ensure required variables are set
    THRESHOLD=${THRESHOLD:-10}
    CHECK_INTERVAL=${CHECK_INTERVAL:-30}
    SUBNET_MASK=${SUBNET_MASK:-24}
    PORTS=${PORTS:-"443"}
    ENABLE_IPV4=${ENABLE_IPV4:-true}
    ENABLE_IPV6=${ENABLE_IPV6:-false}
    AUTO_UNBLOCK_HOURS=${AUTO_UNBLOCK_HOURS:-0}
    SAVE_IPTABLES=${SAVE_IPTABLES:-true}
}

# Ensure we're running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo "Error: This script must be run as root" >&2
        exit 1
    fi
}

# Initialize directories and files
init_files() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    mkdir -p "$(dirname "$WHITELIST_FILE")"
    touch "$LOG_FILE"
    touch "$STATE_FILE"
}

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if IP/subnet is whitelisted
is_whitelisted() {
    local ip_or_subnet=$1
    
    if [[ ! -f "$WHITELIST_FILE" ]]; then
        return 1
    fi
    
    # Check exact IP match
    if grep -qFx "$ip_or_subnet" "$WHITELIST_FILE"; then
        return 0
    fi
    
    # Check if IP is within any whitelisted subnet
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        # Check if it's a subnet (contains /)
        if [[ "$line" == */* ]]; then
            # Use ipcalc or simple check
            if command -v ipcalc &> /dev/null; then
                if ipcalc -c "$ip_or_subnet" "$line" &> /dev/null; then
                    return 0
                fi
            else
                # Simple prefix match for /24
                local whitelist_subnet=$(echo "$line" | cut -d'/' -f1 | cut -d'.' -f1-3)
                local check_subnet=$(echo "$ip_or_subnet" | cut -d'.' -f1-3)
                if [[ "$line" == *"/24"* ]] && [[ "$whitelist_subnet" == "$check_subnet" ]]; then
                    return 0
                fi
            fi
        fi
    done < "$WHITELIST_FILE"
    
    return 1
}

# Extract subnet from IP
get_subnet() {
    local ip=$1
    local mask=$2
    
    if [[ "$ip" =~ : ]]; then
        # IPv6 - extract first 3 hextets for /48
        if [[ "$mask" == "48" ]]; then
            echo "$ip" | cut -d':' -f1-3
        else
            # For other masks, use ipcalc if available
            if command -v ipcalc &> /dev/null; then
                ipcalc -6 "$ip/$mask" | grep Network | awk '{print $2}' | cut -d'/' -f1
            else
                echo "$ip" | cut -d':' -f1-3
            fi
        fi
    else
        # IPv4
        case "$mask" in
            24) echo "$ip" | cut -d'.' -f1-3 ;;
            16) echo "$ip" | cut -d'.' -f1-2 ;;
            8)  echo "$ip" | cut -d'.' -f1 ;;
            *)  echo "$ip" | cut -d'.' -f1-3 ;;  # Default to /24
        esac
    fi
}

# Check if subnet is already blocked
is_blocked() {
    local subnet=$1
    local family=$2  # "4" or "6"
    
    if [[ "$family" == "6" ]]; then
        grep -q "^\[IPv6\]${subnet}" "$STATE_FILE" 2>/dev/null
    else
        grep -q "^\[IPv4\]${subnet}" "$STATE_FILE" 2>/dev/null
    fi
}

# Add iptables rule and log it
block_subnet() {
    local subnet=$1
    local count=$2
    local family=$3  # "4" or "6"
    local full_subnet
    
    if [[ "$family" == "6" ]]; then
        full_subnet="${subnet}::/${SUBNET_MASK}"
        if is_blocked "$subnet" "6"; then
            return
        fi
        
        log "BLOCKING [IPv6]: ${full_subnet} (${count} SYN-RECV connections detected)"
        ip6tables -I INPUT -s "${full_subnet}" -j DROP 2>/dev/null || {
            log "WARNING: Failed to add IPv6 iptables rule (ip6tables may not be available)"
            return
        }
        echo "[IPv6]${subnet}::/${SUBNET_MASK} $(date +%s)" >> "$STATE_FILE"
    else
        full_subnet="${subnet}.0/${SUBNET_MASK}"
        if is_blocked "$subnet" "4"; then
            return
        fi
        
        log "BLOCKING [IPv4]: ${full_subnet} (${count} SYN-RECV connections detected)"
        iptables -I INPUT -s "${full_subnet}" -j DROP
        echo "[IPv4]${subnet}.0/${SUBNET_MASK} $(date +%s)" >> "$STATE_FILE"
    fi
    
    # Save iptables rules persistently
    if [[ "$SAVE_IPTABLES" == "true" ]]; then
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            if [[ "$family" == "6" ]] && command -v ip6tables-save &> /dev/null; then
                ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            fi
        fi
    fi
}

# Auto-unblock old entries
auto_unblock() {
    if [[ "$AUTO_UNBLOCK_HOURS" -eq 0 ]]; then
        return
    fi
    
    local current_time=$(date +%s)
    local unblock_time=$((AUTO_UNBLOCK_HOURS * 3600))
    
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi
        
        local timestamp=$(echo "$line" | awk '{print $2}')
        if [[ -z "$timestamp" ]] || [[ ! "$timestamp" =~ ^[0-9]+$ ]]; then
            continue
        fi
        
        local age=$((current_time - timestamp))
        
        if [[ $age -gt $unblock_time ]]; then
            local subnet_entry=$(echo "$line" | awk '{print $1}')
            local subnet=$(echo "$subnet_entry" | sed 's/^\[IPv[46]\]//')
            local family=$(echo "$subnet_entry" | grep -o 'IPv[46]' | grep -o '[46]')
            
            log "AUTO-UNBLOCKING: ${subnet} (blocked for ${AUTO_UNBLOCK_HOURS} hours)"
            
            if [[ "$family" == "6" ]]; then
                ip6tables -D INPUT -s "$subnet" -j DROP 2>/dev/null || true
            else
                iptables -D INPUT -s "$subnet" -j DROP 2>/dev/null || true
            fi
            
            # Remove from state file
            sed -i "\|^${subnet_entry}|d" "$STATE_FILE"
        fi
    done < "$STATE_FILE"
}

# Main detection loop
detect_and_block() {
    log "Starting DDoS detection scan (ports: ${PORTS})"
    
    declare -A ip_counts
    local total_syn=0
    local ports_array=($PORTS)
    
    # Process each port
    for port in "${ports_array[@]}"; do
        # IPv4 detection
        if [[ "$ENABLE_IPV4" == "true" ]]; then
            while IFS= read -r line; do
                local src_ip=$(echo "$line" | awk '{print $5}' | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
                
                if [[ -z "$src_ip" ]]; then
                    continue
                fi
                
                # Check whitelist
                if is_whitelisted "$src_ip"; then
                    continue
                fi
                
                ((ip_counts["4:$src_ip"]++))
                ((total_syn++))
            done < <(ss -ant | grep 'SYN-RECV' | grep ":${port} " | grep -v ':')
        fi
        
        # IPv6 detection
        if [[ "$ENABLE_IPV6" == "true" ]]; then
            while IFS= read -r line; do
                local src_ip=$(echo "$line" | awk '{print $5}' | grep -Eo '^[0-9a-fA-F:]+' | head -1)
                
                if [[ -z "$src_ip" ]] || [[ "$src_ip" == "::" ]] || [[ "$src_ip" == "::1" ]]; then
                    continue
                fi
                
                # Check whitelist
                if is_whitelisted "$src_ip"; then
                    continue
                fi
                
                ((ip_counts["6:$src_ip"]++))
                ((total_syn++))
            done < <(ss -ant6 | grep 'SYN-RECV' | grep ":${port} " | grep -v '::')
        fi
    done
    
    log "Found $total_syn SYN-RECV connections on monitored ports"
    
    # Aggregate by subnet
    declare -A subnet_counts
    for key in "${!ip_counts[@]}"; do
        local family=$(echo "$key" | cut -d':' -f1)
        local ip=$(echo "$key" | cut -d':' -f2-)
        local subnet=$(get_subnet "$ip" "$SUBNET_MASK")
        local count=${ip_counts[$key]}
        local subnet_key="${family}:${subnet}"
        
        if [[ -n "${subnet_counts[$subnet_key]}" ]]; then
            subnet_counts[$subnet_key]=$((${subnet_counts[$subnet_key]} + count))
        else
            subnet_counts[$subnet_key]=$count
        fi
    done
    
    # Block subnets that exceed threshold
    for subnet_key in "${!subnet_counts[@]}"; do
        local family=$(echo "$subnet_key" | cut -d':' -f1)
        local subnet=$(echo "$subnet_key" | cut -d':' -f2-)
        local count=${subnet_counts[$subnet_key]}
        
        if [[ $count -ge $THRESHOLD ]]; then
            block_subnet "$subnet" "$count" "$family"
        else
            log "Subnet ${subnet} (IPv${family}): $count connections (below threshold of $THRESHOLD)"
        fi
    done
    
    # Auto-unblock old entries
    auto_unblock
    
    # Report summary
    local total_blocked=$(grep -c '^\[IPv' "$STATE_FILE" 2>/dev/null || echo 0)
    log "Scan complete. Total subnets blocked: $total_blocked"
}

# Cleanup function
cleanup() {
    log "DDoS Guard shutting down..."
    rm -f "$LOCK_FILE"
    exit 0
}

# Main execution
main() {
    check_root
    load_config
    init_files
    
    # Create lock file
    if [[ -f "$LOCK_FILE" ]]; then
        local pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if ps -p "$pid" > /dev/null 2>&1; then
            log "Another instance is already running (PID: $pid)"
            exit 1
        fi
    fi
    echo $$ > "$LOCK_FILE"
    
    trap cleanup SIGTERM SIGINT EXIT
    
    log "DDoS Guard started (Threshold: $THRESHOLD, Interval: ${CHECK_INTERVAL}s, Ports: ${PORTS})"
    
    while true; do
        detect_and_block
        sleep "$CHECK_INTERVAL"
    done
}

main "$@"

