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
RATE_TRACKING_FILE="/var/run/ddos-guard.rates"
METRICS_FILE="/var/run/ddos-guard/ddos_guard.prom"
GEOIP_CACHE_FILE="/var/run/ddos-guard.geoip_cache"

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
    
    # Advanced detection options
    DETECTION_MODE=${DETECTION_MODE:-"age"}
    MIN_CONNECTION_AGE=${MIN_CONNECTION_AGE:-3}
    RATE_WINDOW=${RATE_WINDOW:-60}
    PER_IP_RATE_LIMIT=${PER_IP_RATE_LIMIT:-30}
    
    # Metrics and monitoring options
    ENABLE_METRICS=${ENABLE_METRICS:-false}
    METRICS_FILE=${METRICS_FILE:-"/var/run/ddos-guard/ddos_guard.prom"}
    ENABLE_GEOIP=${ENABLE_GEOIP:-false}
    GEOIP_DB_PATH=${GEOIP_DB_PATH:-"/usr/share/GeoIP/GeoLite2-City.mmdb"}
    
    # ASN lookup options
    ENABLE_ASN_LOOKUP=${ENABLE_ASN_LOOKUP:-false}
    ASN_DB_PATH=${ASN_DB_PATH:-"/usr/share/GeoIP/GeoLite2-ASN.mmdb"}
    ASN_LOOKUP_METHOD=${ASN_LOOKUP_METHOD:-"mmdb"}
    
    # Threat intelligence sharing options
    ENABLE_INTEL_SHARING=${ENABLE_INTEL_SHARING:-false}
    INTEL_FEED_URL=${INTEL_FEED_URL:-"https://raw.githubusercontent.com/ddos-guard/threat-intel/main/blocked_subnets.json"}
    INTEL_EXPORT_FILE=${INTEL_EXPORT_FILE:-"/var/run/ddos-guard.intel_export.json"}
    INTEL_FEED_FILE=${INTEL_FEED_FILE:-"/var/run/ddos-guard.intel_feed.json"}
    AUTO_BLOCK_FROM_FEED=${AUTO_BLOCK_FROM_FEED:-false}
    
    # Validate detection mode
    if [[ ! "$DETECTION_MODE" =~ ^(count|age|rate)$ ]]; then
        log "WARNING: Invalid DETECTION_MODE '$DETECTION_MODE', using 'age'"
        DETECTION_MODE="age"
    fi
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
    touch "$RATE_TRACKING_FILE"
    
    # Create metrics directory if enabled
    if [[ "$ENABLE_METRICS" == "true" ]]; then
        local metrics_dir="$(dirname "$METRICS_FILE")"
        if mkdir -p "$metrics_dir" 2>/dev/null && touch "$METRICS_FILE" 2>/dev/null; then
            log "Metrics file initialized: $METRICS_FILE"
        else
            log "WARNING: Cannot create metrics file at $METRICS_FILE (permissions issue)"
            log "WARNING: Metrics disabled. Check directory permissions or use a different path"
            ENABLE_METRICS=false
        fi
    fi
    
    # Create GeoIP cache file if enabled
    if [[ "$ENABLE_GEOIP" == "true" ]]; then
        touch "$GEOIP_CACHE_FILE"
    fi
    
    # Initialize GeoIP and ASN caches
    declare -gA geoip_cache
    declare -gA asn_cache
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
    local reason=$4  # Detection reason
    local full_subnet
    
    if [[ "$family" == "6" ]]; then
        full_subnet="${subnet}::/${SUBNET_MASK}"
        if is_blocked "$subnet" "6"; then
            return
        fi
        
        log "BLOCKING [IPv6]: ${full_subnet} - ${reason} (${count} connections)"
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
        
        log "BLOCKING [IPv4]: ${full_subnet} - ${reason} (${count} connections)"
        iptables -I INPUT -s "${full_subnet}" -j DROP
        echo "[IPv4]${subnet}.0/${SUBNET_MASK} $(date +%s)" >> "$STATE_FILE"
    fi
    
    # Export metrics
    export_metrics
    
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

# Parse connection age from ss output (returns seconds)
parse_connection_age() {
    local timer_str=$1
    
    # ss -o shows timers like: timer:(on,3.456ms,0) or timer:(keepalive,119min,0)
    # Extract the time value
    if [[ "$timer_str" =~ timer:\([^,]+,([0-9.]+)(ms|sec|min|hr) ]]; then
        local value="${BASH_REMATCH[1]}"
        local unit="${BASH_REMATCH[2]}"
        
        case "$unit" in
            ms)  echo "0" ;;  # Less than 1 second
            sec) printf "%.0f" "$value" ;;
            min) printf "%.0f" "$(echo "$value * 60" | bc 2>/dev/null || echo "60")" ;;
            hr)  printf "%.0f" "$(echo "$value * 3600" | bc 2>/dev/null || echo "3600")" ;;
            *)   echo "0" ;;
        esac
    else
        # If we can't parse age, assume it's old enough
        echo "$MIN_CONNECTION_AGE"
    fi
}

# Get GeoIP information for an IP (with caching)
get_geoip_info() {
    local ip=$1
    
    # Check cache first
    if [[ -f "$GEOIP_CACHE_FILE" ]]; then
        local cached=$(grep "^${ip}:" "$GEOIP_CACHE_FILE" 2>/dev/null | cut -d':' -f2-)
        if [[ -n "$cached" ]]; then
            echo "$cached"
            return 0
        fi
    fi
    
    # Try to use GeoIP lookup if available
    local country="unknown"
    local city="unknown"
    local lat="0"
    local lon="0"
    
    # Try mmdblookup (MaxMind GeoLite2)
    if [[ "$ENABLE_GEOIP" == "true" ]] && [[ -f "$GEOIP_DB_PATH" ]] && command -v mmdblookup &> /dev/null; then
        local geoip_output=$(mmdblookup -f "$GEOIP_DB_PATH" -i "$ip" 2>/dev/null)
        if [[ -n "$geoip_output" ]]; then
            country=$(echo "$geoip_output" | grep -A 1 '"country".*"iso_code"' | tail -1 | awk '{print $1}' | tr -d '"' || echo "unknown")
            city=$(echo "$geoip_output" | grep -A 1 '"city".*"names".*"en"' | tail -1 | awk '{print $1}' | tr -d '"' || echo "unknown")
            lat=$(echo "$geoip_output" | grep -A 1 '"location".*"latitude"' | tail -1 | awk '{print $1}' || echo "0")
            lon=$(echo "$geoip_output" | grep -A 1 '"location".*"longitude"' | tail -1 | awk '{print $1}' || echo "0")
        fi
    fi
    
    # Cache the result
    echo "${ip}:${country}:${city}:${lat}:${lon}" >> "$GEOIP_CACHE_FILE" 2>/dev/null || true
    
    echo "${country}:${city}:${lat}:${lon}"
}

# Get ASN (Autonomous System Number) information for an IP
get_asn_info() {
    local ip=$1
    
    # Check cache first
    if [[ -n "${asn_cache[$ip]:-}" ]]; then
        echo "${asn_cache[$ip]}"
        return
    fi
    
    local asn="unknown"
    local as_name="unknown"
    local as_org="unknown"
    
    if [[ "$ENABLE_ASN_LOOKUP" != "true" ]]; then
        echo "${asn}:${as_name}:${as_org}"
        return
    fi
    
    case "$ASN_LOOKUP_METHOD" in
        mmdb)
            # MaxMind GeoLite2-ASN database lookup
            if [[ -f "$ASN_DB_PATH" ]] && command -v mmdblookup &> /dev/null; then
                local asn_output=$(mmdblookup -f "$ASN_DB_PATH" -i "$ip" 2>/dev/null)
                if [[ -n "$asn_output" ]]; then
                    # Extract ASN number
                    local asn_num=$(echo "$asn_output" | grep "autonomous_system_number" | grep -oE '[0-9]+' | head -1)
                    if [[ -n "$asn_num" ]]; then
                        asn="AS${asn_num}"
                    fi
                    
                    # Extract organization name
                    local org_line=$(echo "$asn_output" | grep "autonomous_system_organization" | head -1)
                    if [[ -n "$org_line" ]]; then
                        as_org=$(echo "$org_line" | sed 's/.*"\(.*\)".*/\1/' | head -1)
                        # Get short name (first word, uppercase, remove special chars)
                        as_name=$(echo "$as_org" | awk '{print toupper($1)}' | sed 's/[^A-Z0-9-]//g' | cut -c1-20)
                    fi
                fi
            fi
            ;;
        cymru)
            # Team Cymru DNS-based lookup (requires network access)
            if command -v dig &> /dev/null; then
                # Reverse IP for DNS query
                local reversed=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
                local cymru_result=$(dig +short TXT "${reversed}.origin.asn.cymru.com" 2>/dev/null | head -1 | tr -d '"')
                
                if [[ -n "$cymru_result" ]]; then
                    local asn_num=$(echo "$cymru_result" | awk -F'|' '{print $1}' | tr -d ' ')
                    if [[ -n "$asn_num" ]]; then
                        asn="AS${asn_num}"
                        
                        # Get AS name with another query
                        local as_result=$(dig +short TXT "AS${asn_num}.asn.cymru.com" 2>/dev/null | head -1 | tr -d '"')
                        if [[ -n "$as_result" ]]; then
                            as_org=$(echo "$as_result" | awk -F'|' '{print $5}' | sed 's/^ *//;s/ *$//')
                            as_name=$(echo "$as_org" | awk '{print toupper($1)}' | sed 's/[^A-Z0-9-]//g' | cut -c1-20)
                        fi
                    fi
                fi
            fi
            ;;
    esac
    
    local result="${asn}:${as_name}:${as_org}"
    
    # Store in cache
    asn_cache[$ip]="$result"
    
    echo "$result"
}

# Export Prometheus metrics
export_metrics() {
    if [[ "$ENABLE_METRICS" != "true" ]]; then
        return
    fi
    
    local metrics_tmp="${METRICS_FILE}.tmp"
    
    # Write metrics header
    cat > "$metrics_tmp" <<EOF
# HELP ddos_guard_blocked_subnets_total Total number of subnets currently blocked
# TYPE ddos_guard_blocked_subnets_total gauge
EOF
    
    # Count blocked subnets
    local total_blocked=0
    local ipv4_blocked=0
    local ipv6_blocked=0
    
    if [[ -f "$STATE_FILE" ]]; then
        # Use awk for reliable counting (always outputs clean numeric values)
        total_blocked=$(awk '/^\[IPv/ {count++} END {print count+0}' "$STATE_FILE" 2>/dev/null)
        ipv4_blocked=$(awk '/^\[IPv4\]/ {count++} END {print count+0}' "$STATE_FILE" 2>/dev/null)
        ipv6_blocked=$(awk '/^\[IPv6\]/ {count++} END {print count+0}' "$STATE_FILE" 2>/dev/null)
    fi
    
    cat >> "$metrics_tmp" <<EOF
ddos_guard_blocked_subnets_total{family="all"} $total_blocked
ddos_guard_blocked_subnets_total{family="ipv4"} $ipv4_blocked
ddos_guard_blocked_subnets_total{family="ipv6"} $ipv6_blocked
EOF
    
    # Export individual blocked subnets with GeoIP data
    if [[ -f "$STATE_FILE" ]] && [[ "$ENABLE_GEOIP" == "true" ]]; then
        cat >> "$metrics_tmp" <<EOF

# HELP ddos_guard_blocked_subnet_info Information about blocked subnets
# TYPE ddos_guard_blocked_subnet_info gauge
EOF
        
        while IFS= read -r line; do
            if [[ -z "$line" ]]; then
                continue
            fi
            
            local subnet_entry=$(echo "$line" | awk '{print $1}')
            local timestamp=$(echo "$line" | awk '{print $2}')
            
            if [[ -z "$subnet_entry" ]] || [[ -z "$timestamp" ]]; then
                continue
            fi
            
            # Extract subnet and family
            local subnet=$(echo "$subnet_entry" | sed 's/^\[IPv[46]\]//' | cut -d'/' -f1)
            local family=$(echo "$subnet_entry" | grep -o 'IPv[46]' | grep -o '[46]')
            
            # Get GeoIP info (use first IP in subnet for lookup)
            local lookup_ip="$subnet"
            if [[ "$family" == "4" ]]; then
                # If subnet is just prefix (e.g., "192.0.2"), add .1
                if [[ ! "$subnet" =~ \. ]]; then
                    lookup_ip="${subnet}.0.0.1"
                elif [[ $(echo "$subnet" | tr -cd '.' | wc -c) -eq 1 ]]; then
                    lookup_ip="${subnet}.0.1"
                elif [[ $(echo "$subnet" | tr -cd '.' | wc -c) -eq 2 ]]; then
                    lookup_ip="${subnet}.1"
                fi
            fi
            
            local geoip_info=$(get_geoip_info "$lookup_ip")
            local country=$(echo "$geoip_info" | cut -d':' -f1)
            local city=$(echo "$geoip_info" | cut -d':' -f2)
            local lat=$(echo "$geoip_info" | cut -d':' -f3)
            local lon=$(echo "$geoip_info" | cut -d':' -f4)
            
            # Get ASN info if enabled
            local asn="unknown"
            local as_name="unknown"
            if [[ "$ENABLE_ASN_LOOKUP" == "true" ]]; then
                local asn_info=$(get_asn_info "$lookup_ip")
                asn=$(echo "$asn_info" | cut -d':' -f1)
                as_name=$(echo "$asn_info" | cut -d':' -f2)
            fi
            
            # Escape special characters for Prometheus
            subnet=$(echo "$subnet_entry" | sed 's/^\[IPv[46]\]//')
            country=$(echo "$country" | sed 's/"/\\"/g')
            city=$(echo "$city" | sed 's/"/\\"/g')
            asn=$(echo "$asn" | sed 's/"/\\"/g')
            as_name=$(echo "$as_name" | sed 's/"/\\"/g')
            
            cat >> "$metrics_tmp" <<EOF
ddos_guard_blocked_subnet_info{subnet="$subnet",family="ipv${family}",country="$country",city="$city",latitude="$lat",longitude="$lon",asn="$asn",as_name="$as_name"} 1
EOF
        done < "$STATE_FILE"
    fi
    
    # Export detection statistics
    cat >> "$metrics_tmp" <<EOF

# HELP ddos_guard_scans_total Total number of detection scans performed
# TYPE ddos_guard_scans_total counter
# NOTE: This metric is incremented on each scan, actual value managed externally

# HELP ddos_guard_blocks_total Total number of blocks performed
# TYPE ddos_guard_blocks_total counter
# NOTE: This metric is incremented on each block, actual value managed externally
EOF
    
    # Atomic write
    mv "$metrics_tmp" "$METRICS_FILE" 2>/dev/null || true
}

# Export blocked subnets for threat intelligence sharing
export_threat_intel() {
    if [[ "$ENABLE_INTEL_SHARING" != "true" ]]; then
        return
    fi
    
    if [[ ! -f "$STATE_FILE" ]]; then
        return
    fi
    
    local intel_tmp="${INTEL_EXPORT_FILE}.tmp"
    local current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Start JSON array
    echo "{" > "$intel_tmp"
    echo "  \"version\": \"1.0\"," >> "$intel_tmp"
    echo "  \"generated_at\": \"${current_time}\"," >> "$intel_tmp"
    echo "  \"source\": \"ddos-guard\"," >> "$intel_tmp"
    echo "  \"blocked_subnets\": [" >> "$intel_tmp"
    
    local first=true
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi
        
        local subnet_entry=$(echo "$line" | awk '{print $1}')
        local timestamp=$(echo "$line" | awk '{print $2}')
        
        if [[ -z "$subnet_entry" ]] || [[ -z "$timestamp" ]]; then
            continue
        fi
        
        # Extract subnet and family
        local subnet=$(echo "$subnet_entry" | sed 's/^\[IPv[46]\]//')
        local family=$(echo "$subnet_entry" | grep -o 'IPv[46]')
        
        # Get GeoIP info if enabled
        local country="unknown"
        local geoip_info=""
        if [[ "$ENABLE_GEOIP" == "true" ]]; then
            local lookup_ip=$(echo "$subnet" | cut -d'/' -f1 | sed 's/\.0$/\.1/')
            geoip_info=$(get_geoip_info "$lookup_ip" 2>/dev/null || echo "unknown:unknown:0:0")
            country=$(echo "$geoip_info" | cut -d':' -f1)
        fi
        
        # Get ASN info if enabled
        local asn="unknown"
        local as_name="unknown"
        local as_org="unknown"
        if [[ "$ENABLE_ASN_LOOKUP" == "true" ]]; then
            local lookup_ip=$(echo "$subnet" | cut -d'/' -f1 | sed 's/\.0$/\.1/')
            local asn_info=$(get_asn_info "$lookup_ip" 2>/dev/null || echo "unknown:unknown:unknown")
            asn=$(echo "$asn_info" | cut -d':' -f1)
            as_name=$(echo "$asn_info" | cut -d':' -f2)
            as_org=$(echo "$asn_info" | cut -d':' -f3)
        fi
        
        # Add comma if not first entry
        if [[ "$first" == "false" ]]; then
            echo "," >> "$intel_tmp"
        fi
        first=false
        
        # Write subnet entry
        cat >> "$intel_tmp" <<EOF
    {
      "subnet": "${subnet}",
      "family": "${family}",
      "first_seen": "${timestamp}",
      "country": "${country}",
      "asn": "${asn}",
      "as_name": "${as_name}",
      "as_organization": "${as_org}"
    }
EOF
    done < "$STATE_FILE"
    
    # Close JSON
    echo "" >> "$intel_tmp"
    echo "  ]" >> "$intel_tmp"
    echo "}" >> "$intel_tmp"
    
    # Atomic write
    mv "$intel_tmp" "$INTEL_EXPORT_FILE" 2>/dev/null || true
    
    log "Threat intelligence exported to ${INTEL_EXPORT_FILE}"
}

# Download threat intelligence feed from GitHub
download_threat_intel() {
    if [[ "$ENABLE_INTEL_SHARING" != "true" ]]; then
        return
    fi
    
    log "Downloading threat intelligence feed from ${INTEL_FEED_URL}"
    
    # Download with curl or wget
    if command -v curl &> /dev/null; then
        curl -s -f -o "${INTEL_FEED_FILE}.tmp" "$INTEL_FEED_URL" 2>/dev/null || {
            log "WARNING: Failed to download threat intel feed"
            return 1
        }
    elif command -v wget &> /dev/null; then
        wget -q -O "${INTEL_FEED_FILE}.tmp" "$INTEL_FEED_URL" 2>/dev/null || {
            log "WARNING: Failed to download threat intel feed"
            return 1
        }
    else
        log "WARNING: Neither curl nor wget available for downloading threat intel"
        return 1
    fi
    
    # Validate JSON (basic check)
    if grep -q "blocked_subnets" "${INTEL_FEED_FILE}.tmp" 2>/dev/null; then
        mv "${INTEL_FEED_FILE}.tmp" "$INTEL_FEED_FILE"
        log "Threat intelligence feed downloaded successfully"
        return 0
    else
        log "WARNING: Downloaded threat intel feed is invalid"
        rm -f "${INTEL_FEED_FILE}.tmp"
        return 1
    fi
}

# Apply blocks from threat intelligence feed
apply_threat_intel() {
    if [[ "$ENABLE_INTEL_SHARING" != "true" ]] || [[ "$AUTO_BLOCK_FROM_FEED" != "true" ]]; then
        return
    fi
    
    if [[ ! -f "$INTEL_FEED_FILE" ]]; then
        log "No threat intelligence feed found, skipping"
        return
    fi
    
    log "Applying blocks from threat intelligence feed"
    
    local blocks_added=0
    
    # Parse JSON and extract subnets (using grep/awk for simplicity)
    while IFS= read -r subnet_line; do
        # Extract subnet value from JSON line like: "subnet": "192.0.2.0/24",
        local subnet=$(echo "$subnet_line" | grep -oP '"subnet":\s*"\K[^"]+' || true)
        
        if [[ -z "$subnet" ]]; then
            continue
        fi
        
        # Determine family from subnet format
        local family="4"
        if [[ "$subnet" =~ : ]]; then
            family="6"
        fi
        
        # Check if already blocked
        local subnet_prefix=$(echo "$subnet" | cut -d'/' -f1 | sed 's/\.0$//')
        if is_blocked "$subnet_prefix" "$family"; then
            continue
        fi
        
        # Check if whitelisted
        if is_whitelisted "$subnet"; then
            log "Skipping whitelisted subnet from feed: ${subnet}"
            continue
        fi
        
        # Add iptables rule
        log "BLOCKING [IPv${family}] from threat intel: ${subnet}"
        
        if [[ "$family" == "6" ]]; then
            ip6tables -I INPUT -s "${subnet}" -j DROP 2>/dev/null || continue
            echo "[IPv6]${subnet} $(date +%s)" >> "$STATE_FILE"
        else
            iptables -I INPUT -s "${subnet}" -j DROP 2>/dev/null || continue
            echo "[IPv4]${subnet} $(date +%s)" >> "$STATE_FILE"
        fi
        
        ((blocks_added++))
    done < <(grep '"subnet"' "$INTEL_FEED_FILE" 2>/dev/null)
    
    if [[ $blocks_added -gt 0 ]]; then
        log "Applied ${blocks_added} blocks from threat intelligence feed"
        export_metrics
    fi
}

# Update rate tracking (for PER_IP_RATE_LIMIT - works in all detection modes)
update_rate_tracking() {
    local ip=$1
    local current_time=$(date +%s)
    
    # Format: IP timestamp
    echo "$ip $current_time" >> "$RATE_TRACKING_FILE"
    
    # Clean old entries (older than RATE_WINDOW)
    local cutoff_time=$((current_time - RATE_WINDOW))
    if [[ -f "$RATE_TRACKING_FILE" ]]; then
        # Keep only recent entries
        grep -v "^$" "$RATE_TRACKING_FILE" | awk -v cutoff="$cutoff_time" '$2 >= cutoff' > "${RATE_TRACKING_FILE}.tmp" 2>/dev/null || true
        mv "${RATE_TRACKING_FILE}.tmp" "$RATE_TRACKING_FILE" 2>/dev/null || true
    fi
}

# Get connection rate for an IP (connections per minute)
get_ip_rate() {
    local ip=$1
    local current_time=$(date +%s)
    local cutoff_time=$((current_time - 60))
    
    if [[ ! -f "$RATE_TRACKING_FILE" ]]; then
        echo "0"
        return
    fi
    
    # Count entries for this IP in the last 60 seconds
    grep "^$ip " "$RATE_TRACKING_FILE" 2>/dev/null | awk -v cutoff="$cutoff_time" '$2 >= cutoff' | wc -l | tr -d ' '
}

# Main detection loop
detect_and_block() {
    log "Starting DDoS detection scan (mode: ${DETECTION_MODE}, ports: ${PORTS})"
    
    declare -A ip_counts
    declare -A ip_reasons
    local total_syn=0
    local ports_array=($PORTS)
    local current_time=$(date +%s)
    
    # Process each port
    for port in "${ports_array[@]}"; do
        # IPv4 detection
        if [[ "$ENABLE_IPV4" == "true" ]]; then
            local ss_cmd="ss -ant"
            if [[ "$DETECTION_MODE" == "age" ]]; then
                ss_cmd="ss -anto"  # Include timer info for age detection
            fi
            
            while IFS= read -r line; do
                local src_ip=$(echo "$line" | awk '{print $5}' | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
                
                if [[ -z "$src_ip" ]]; then
                    continue
                fi
                
                # Check whitelist
                if is_whitelisted "$src_ip"; then
                    continue
                fi
                
                # Age-based filtering
                if [[ "$DETECTION_MODE" == "age" ]]; then
                    # Try Perl regex first, fallback to extended regex if not supported
                    local timer_info=$(echo "$line" | grep -oP 'timer:\([^)]+\)' 2>/dev/null || echo "$line" | grep -oE 'timer:\([^)]+\)' || echo "")
                    if [[ -n "$timer_info" ]]; then
                        local age=$(parse_connection_age "$timer_info")
                        if [[ "$age" -lt "$MIN_CONNECTION_AGE" ]]; then
                            continue  # Skip young connections
                        fi
                    fi
                fi
                
                # Rate tracking for PER_IP_RATE_LIMIT (works in all modes)
                if [[ "$PER_IP_RATE_LIMIT" -gt 0 ]]; then
                    update_rate_tracking "4:$src_ip"
                fi
                
                ip_counts["4:$src_ip"]=$((${ip_counts["4:$src_ip"]:-0} + 1))
                ((total_syn++))
            done < <($ss_cmd 2>/dev/null | grep 'SYN-RECV' 2>/dev/null | grep ":${port} " 2>/dev/null || true)
        fi
        
        # IPv6 detection
        if [[ "$ENABLE_IPV6" == "true" ]]; then
            local ss_cmd="ss -ant6"
            if [[ "$DETECTION_MODE" == "age" ]]; then
                ss_cmd="ss -ant6o"
            fi
            
            while IFS= read -r line; do
                local src_ip=$(echo "$line" | awk '{print $5}' | grep -Eo '^[0-9a-fA-F:]+' | head -1 || true)
                
                if [[ -z "$src_ip" ]] || [[ "$src_ip" == "::" ]] || [[ "$src_ip" == "::1" ]]; then
                    continue
                fi
                
                # Check whitelist
                if is_whitelisted "$src_ip"; then
                    continue
                fi
                
                # Age-based filtering
                if [[ "$DETECTION_MODE" == "age" ]]; then
                    # Try Perl regex first, fallback to extended regex if not supported
                    local timer_info=$(echo "$line" | grep -oP 'timer:\([^)]+\)' 2>/dev/null || echo "$line" | grep -oE 'timer:\([^)]+\)' || echo "")
                    if [[ -n "$timer_info" ]]; then
                        local age=$(parse_connection_age "$timer_info")
                        if [[ "$age" -lt "$MIN_CONNECTION_AGE" ]]; then
                            continue
                        fi
                    fi
                fi
                
                # Rate tracking for PER_IP_RATE_LIMIT (works in all modes)
                if [[ "$PER_IP_RATE_LIMIT" -gt 0 ]]; then
                    update_rate_tracking "6:$src_ip"
                fi
                
                ip_counts["6:$src_ip"]=$((${ip_counts["6:$src_ip"]:-0} + 1))
                ((total_syn++))
            done < <($ss_cmd 2>/dev/null | grep 'SYN-RECV' 2>/dev/null | grep ":${port} " 2>/dev/null | grep -v '::' 2>/dev/null || true)
        fi
    done
    
    local detection_method=""
    case "$DETECTION_MODE" in
        age) detection_method="connections older than ${MIN_CONNECTION_AGE}s" ;;
        rate) detection_method="connections in ${RATE_WINDOW}s window" ;;
        *) detection_method="total connections" ;;
    esac
    
    log "Found $total_syn qualifying SYN-RECV ${detection_method}"
    
    # Check per-IP rate limits (if enabled)
    if [[ "$PER_IP_RATE_LIMIT" -gt 0 ]]; then
        for key in "${!ip_counts[@]}"; do
            local family=$(echo "$key" | cut -d':' -f1)
            local ip=$(echo "$key" | cut -d':' -f2-)
            local rate=$(get_ip_rate "$key")
            
            if [[ "$rate" -ge "$PER_IP_RATE_LIMIT" ]]; then
                local subnet=$(get_subnet "$ip" "$SUBNET_MASK")
                local reason="Per-IP rate limit exceeded: ${rate}/min"
                ip_reasons["${family}:${subnet}"]="$reason"
                log "WARNING: IP ${ip} exceeded rate limit: ${rate} conn/min (limit: ${PER_IP_RATE_LIMIT})"
            fi
        done
    fi
    
    # Aggregate by subnet
    declare -A subnet_counts
    for key in "${!ip_counts[@]}"; do
        local family=$(echo "$key" | cut -d':' -f1)
        local ip=$(echo "$key" | cut -d':' -f2-)
        local subnet=$(get_subnet "$ip" "$SUBNET_MASK")
        local count=${ip_counts[$key]}
        local subnet_key="${family}:${subnet}"
        
        # Use default value syntax to avoid unbound variable errors
        local existing_count=${subnet_counts[$subnet_key]:-0}
        subnet_counts[$subnet_key]=$((existing_count + count))
        
        # Set default reason if not already set
        if [[ -z "${ip_reasons[$subnet_key]:-}" ]]; then
            ip_reasons[$subnet_key]="Threshold exceeded (mode: ${DETECTION_MODE})"
        fi
    done
    
    # Block subnets that exceed threshold
    for subnet_key in "${!subnet_counts[@]}"; do
        local family=$(echo "$subnet_key" | cut -d':' -f1)
        local subnet=$(echo "$subnet_key" | cut -d':' -f2-)
        local count=${subnet_counts[$subnet_key]:-0}
        local reason="${ip_reasons[$subnet_key]:-Threshold exceeded (mode: ${DETECTION_MODE})}"
        
        if [[ $count -ge $THRESHOLD ]]; then
            block_subnet "$subnet" "$count" "$family" "$reason"
        else
            log "Subnet ${subnet} (IPv${family}): $count connections (below threshold of $THRESHOLD)"
        fi
    done
    
    # Auto-unblock old entries
    auto_unblock
    
    # Report summary
    local total_blocked=0
    if [[ -f "$STATE_FILE" ]]; then
        total_blocked=$(grep -c '^\[IPv' "$STATE_FILE" 2>/dev/null || echo 0)
    fi
    log "Scan complete. Total subnets blocked: $total_blocked"
    
    # Export metrics after scan
    export_metrics
    
    # Export threat intelligence
    export_threat_intel
}

# Cleanup function
cleanup() {
    log "DDoS Guard shutting down..."
    rm -f "$LOCK_FILE"
    rm -f "$RATE_TRACKING_FILE"
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
    
    log "DDoS Guard started"
    log "  Detection Mode: ${DETECTION_MODE}"
    log "  Threshold: ${THRESHOLD} connections"
    log "  Interval: ${CHECK_INTERVAL}s"
    log "  Ports: ${PORTS}"
    log "  Subnet Mask: /${SUBNET_MASK}"
    
    if [[ "$DETECTION_MODE" == "age" ]]; then
        log "  Min Connection Age: ${MIN_CONNECTION_AGE}s (filters fast legitimate connections)"
    elif [[ "$DETECTION_MODE" == "rate" ]]; then
        log "  Rate Window: ${RATE_WINDOW}s (tracks new connections over time)"
    fi
    
    if [[ "$PER_IP_RATE_LIMIT" -gt 0 ]]; then
        log "  Per-IP Rate Limit: ${PER_IP_RATE_LIMIT} conn/min"
    fi
    
    # Download and apply threat intelligence feed on startup
    if [[ "$ENABLE_INTEL_SHARING" == "true" ]]; then
        log "Threat Intelligence: ENABLED"
        download_threat_intel
        apply_threat_intel
    fi
    
    while true; do
        detect_and_block || log "WARNING: Detection scan encountered an error, continuing..."
        sleep "$CHECK_INTERVAL"
    done
}

main "$@"

