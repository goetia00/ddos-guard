#!/bin/bash
# install.sh - DDoS Guard Installer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ddos-guard"
SYSTEMD_DIR="/etc/systemd/system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    for cmd in ss iptables systemctl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing[*]}"
        log_info "Please install: ss (iproute2), iptables, systemd"
        exit 1
    fi
    
    log_info "All dependencies found"
}

# Install main script
install_script() {
    log_info "Installing ddos-guard.sh..."
    
    if [[ ! -f "$SCRIPT_DIR/ddos-guard.sh" ]]; then
        log_error "ddos-guard.sh not found in $SCRIPT_DIR"
        exit 1
    fi
    
    cp "$SCRIPT_DIR/ddos-guard.sh" "$INSTALL_DIR/ddos-guard.sh"
    chmod +x "$INSTALL_DIR/ddos-guard.sh"
    
    log_info "Script installed to $INSTALL_DIR/ddos-guard.sh"
}

# Install configuration files
install_config() {
    log_info "Installing configuration files..."
    
    mkdir -p "$CONFIG_DIR"
    
    # Install config file if it doesn't exist
    if [[ ! -f "$CONFIG_DIR/ddos-guard.conf" ]]; then
        if [[ -f "$SCRIPT_DIR/ddos-guard.conf" ]]; then
            cp "$SCRIPT_DIR/ddos-guard.conf" "$CONFIG_DIR/ddos-guard.conf"
            log_info "Configuration file installed"
        else
            # Create default config
            cat > "$CONFIG_DIR/ddos-guard.conf" << 'EOF'
THRESHOLD=10
CHECK_INTERVAL=30
SUBNET_MASK=24
PORTS="443"
ENABLE_IPV4=true
ENABLE_IPV6=false
AUTO_UNBLOCK_HOURS=0
SAVE_IPTABLES=true
EOF
            log_info "Default configuration file created"
        fi
    else
        log_warn "Configuration file already exists, skipping..."
    fi
    
    # Install whitelist file if it doesn't exist
    if [[ ! -f "$CONFIG_DIR/whitelist.txt" ]]; then
        if [[ -f "$SCRIPT_DIR/whitelist.txt" ]]; then
            cp "$SCRIPT_DIR/whitelist.txt" "$CONFIG_DIR/whitelist.txt"
        else
            touch "$CONFIG_DIR/whitelist.txt"
            echo "# Whitelist of IPs/subnets that should never be blocked" > "$CONFIG_DIR/whitelist.txt"
        fi
        log_info "Whitelist file created"
    else
        log_warn "Whitelist file already exists, skipping..."
    fi
    
    chmod 600 "$CONFIG_DIR/ddos-guard.conf"
    chmod 644 "$CONFIG_DIR/whitelist.txt"
}

# Install systemd service
install_systemd() {
    log_info "Installing systemd service..."
    
    if [[ ! -f "$SCRIPT_DIR/ddos-guard.service" ]]; then
        log_error "ddos-guard.service not found in $SCRIPT_DIR"
        exit 1
    fi
    
    cp "$SCRIPT_DIR/ddos-guard.service" "$SYSTEMD_DIR/ddos-guard.service"
    systemctl daemon-reload
    
    log_info "Systemd service installed"
}

# Create iptables directory if needed
setup_iptables() {
    log_info "Setting up iptables persistence..."
    
    if [[ ! -d "/etc/iptables" ]]; then
        mkdir -p /etc/iptables
        log_info "Created /etc/iptables directory"
    fi
    
    # Check for iptables-persistent
    local has_persistent=false
    
    # Check Debian/Ubuntu
    if command -v dpkg &> /dev/null && dpkg -l | grep -q iptables-persistent 2>/dev/null; then
        has_persistent=true
    fi
    
    # Check RHEL/CentOS
    if command -v rpm &> /dev/null && rpm -qa | grep -q iptables-services 2>/dev/null; then
        has_persistent=true
    fi
    
    if [[ "$has_persistent" == "false" ]]; then
        log_warn "iptables-persistent not installed"
        log_info "Rules will be saved but may not persist across reboots"
        log_info "Install with: apt install iptables-persistent (Debian/Ubuntu)"
        log_info "Or: yum install iptables-services (RHEL/CentOS)"
    else
        log_info "iptables-persistent is installed"
    fi
}

# Enable and start service
enable_service() {
    log_info "Enabling ddos-guard service..."
    
    systemctl enable ddos-guard.service
    
    read -p "Start the service now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl start ddos-guard.service
        sleep 2
        if systemctl is-active --quiet ddos-guard.service; then
            log_info "Service started successfully"
        else
            log_error "Service failed to start. Check logs with: journalctl -u ddos-guard"
            exit 1
        fi
    else
        log_info "Service enabled but not started. Start with: systemctl start ddos-guard"
    fi
}

# Main installation
main() {
    log_info "DDoS Guard Installation"
    log_info "========================"
    
    check_root
    check_dependencies
    install_script
    install_config
    install_systemd
    setup_iptables
    enable_service
    
    log_info ""
    log_info "Installation complete!"
    log_info ""
    log_info "Configuration: $CONFIG_DIR/ddos-guard.conf"
    log_info "Whitelist: $CONFIG_DIR/whitelist.txt"
    log_info "Logs: /var/log/ddos-guard.log"
    log_info ""
    log_info "Useful commands:"
    log_info "  systemctl status ddos-guard"
    log_info "  journalctl -u ddos-guard -f"
    log_info "  cat /var/run/ddos-guard.state  # View blocked subnets"
}

main "$@"

