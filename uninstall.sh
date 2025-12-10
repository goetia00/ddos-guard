#!/bin/bash
# uninstall.sh - DDoS Guard Uninstaller

set -euo pipefail

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ddos-guard"
SYSTEMD_DIR="/etc/systemd/system"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root" >&2
        exit 1
    fi
}

main() {
    check_root
    
    echo "Uninstalling DDoS Guard..."
    
    # Stop and disable service
    if systemctl is-active --quiet ddos-guard.service 2>/dev/null; then
        systemctl stop ddos-guard.service
    fi
    if systemctl is-enabled --quiet ddos-guard.service 2>/dev/null; then
        systemctl disable ddos-guard.service
    fi
    
    # Remove files
    rm -f "$INSTALL_DIR/ddos-guard.sh"
    rm -f "$SYSTEMD_DIR/ddos-guard.service"
    
    systemctl daemon-reload
    
    read -p "Remove configuration files? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
    fi
    
    read -p "Remove log files? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f /var/log/ddos-guard.log
        rm -f /var/run/ddos-guard.state
    fi
    
    echo "Uninstallation complete!"
    echo ""
    echo "Note: iptables rules created by ddos-guard are NOT automatically removed."
    echo "You may want to review and clean them manually with: iptables -L -n"
}

main "$@"

