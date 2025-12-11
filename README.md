# DDoS Guard

Simple SYN flood detection and mitigation for Linux servers using iptables.

## Overview

DDoS Guard is a lightweight systemd service that monitors for SYN flood attacks and automatically blocks attacking IP subnets using iptables. It's designed for small to medium-scale attacks where blocking at the host level is sufficient.

## Features

- ✅ Automatic SYN flood detection via `ss` command
- ✅ Configurable threshold and monitoring intervals
- ✅ Whitelist support for trusted IPs/subnets
- ✅ IPv4 and IPv6 support
- ✅ Multiple port monitoring
- ✅ Auto-unblock after configurable time period
- ✅ Systemd integration with proper logging
- ✅ Persistent iptables rules
- ✅ Zero dependencies beyond standard Linux tools

## When to Use

✅ **Good for:**
- Small-medium VPS under SYN flood attack
- Budget-conscious operations
- Attacks from limited IP ranges (script kiddies, small botnets)
- Quick automated response to persistent low-level attacks

❌ **Not suitable for:**
- Volumetric attacks (>1Gbps saturating your bandwidth)
- Distributed attacks from millions of IPs
- Layer 7 (HTTP) DDoS attacks
- Attacks requiring upstream filtering

For serious attacks, use [CloudFlare](https://www.cloudflare.com/), [Imperva](https://www.imperva.com/), or similar services.

## Requirements

- Linux (tested on Debian/Ubuntu, RHEL/CentOS)
- Root/sudo access
- `ss` command (iproute2 package)
- `iptables` (and optionally `ip6tables` for IPv6)
- systemd
- `iptables-persistent` (optional, for rule persistence across reboots)

## Quick Install

```bash
git clone https://github.com/goetia00/ddos-guard.git
cd ddos-guard
sudo ./install.sh
```

## Manual Installation

1. Copy files to system locations:
```bash
sudo cp ddos-guard.sh /usr/local/bin/ddos-guard.sh
sudo chmod +x /usr/local/bin/ddos-guard.sh
sudo cp ddos-guard.service /etc/systemd/system/
sudo mkdir -p /etc/ddos-guard
sudo cp ddos-guard.conf /etc/ddos-guard/
sudo cp whitelist.txt /etc/ddos-guard/
```

2. Configure (edit `/etc/ddos-guard/ddos-guard.conf`):
```bash
sudo vim /etc/ddos-guard/ddos-guard.conf
```

3. Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ddos-guard
sudo systemctl start ddos-guard
```

## Configuration

Edit `/etc/ddos-guard/ddos-guard.conf`:

```bash
# Number of SYN-RECV connections from a subnet to trigger blocking
THRESHOLD=10

# Seconds between detection scans
CHECK_INTERVAL=30

# Subnet mask to block (24 = /24, 16 = /16, etc.)
SUBNET_MASK=24

# Ports to monitor (space-separated)
PORTS="443 80"

# Enable IPv4 detection
ENABLE_IPV4=true

# Enable IPv6 detection
ENABLE_IPV6=false

# Auto-unblock after X hours (0 = never unblock)
AUTO_UNBLOCK_HOURS=0

# Save iptables rules persistently
SAVE_IPTABLES=true
```

## Whitelist

Add trusted IPs/subnets to `/etc/ddos-guard/whitelist.txt`:

```
# Your office IP
203.0.113.42

# Your home subnet
198.51.100.0/24

# Monitoring service
192.0.2.100
```

## Usage

### Check Status
```bash
sudo systemctl status ddos-guard
```

### View Logs
```bash
# Follow logs in real-time
sudo journalctl -u ddos-guard -f

# View log file
sudo tail -f /var/log/ddos-guard.log
```

### View Blocked Subnets
```bash
sudo cat /var/run/ddos-guard.state
```

### Manually Unblock a Subnet
```bash
# Remove iptables rule
sudo iptables -D INPUT -s 138.121.245.0/24 -j DROP

# Remove from state file
sudo sed -i '/138.121.245.0\/24/d' /var/run/ddos-guard.state
```

### Restart Service
```bash
sudo systemctl restart ddos-guard
```

## How It Works

1. Every `CHECK_INTERVAL` seconds, the script runs `ss -ant` to find SYN-RECV connections
2. It aggregates connections by source IP and calculates subnet counts
3. If a subnet exceeds `THRESHOLD` connections, it blocks the entire `/24` (or configured mask) subnet
4. Blocked subnets are logged and saved to state file
5. iptables rules are added to drop traffic from blocked subnets

## Limitations

- **Bandwidth already consumed**: iptables blocks at host level, so traffic still hits your network interface
- **Not for volumetric attacks**: If your pipe is saturated, this won't help
- **Host-level only**: Can't protect against upstream saturation
- **Best for limited IP ranges**: Won't help if attack comes from 1000+ different subnets

## Troubleshooting

### Service won't start
```bash
# Check logs
sudo journalctl -u ddos-guard -n 50

# Check if script is executable
ls -l /usr/local/bin/ddos-guard.sh

# Test script manually
sudo /usr/local/bin/ddos-guard.sh
```

### Rules not persisting
```bash
# Install iptables-persistent
sudo apt install iptables-persistent  # Debian/Ubuntu
sudo yum install iptables-services    # RHEL/CentOS
```

### Too many false positives
- Increase `THRESHOLD` in config
- Add legitimate IPs to whitelist
- Check if your monitoring tools are triggering it

## Uninstallation

```bash
sudo ./uninstall.sh
```

Or manually:
```bash
sudo systemctl stop ddos-guard
sudo systemctl disable ddos-guard
sudo rm /usr/local/bin/ddos-guard.sh
sudo rm /etc/systemd/system/ddos-guard.service
sudo systemctl daemon-reload
```

**Note**: iptables rules created by ddos-guard are NOT automatically removed. Review and clean them manually.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details

## Related Projects

- [fail2ban](https://github.com/fail2ban/fail2ban) - Intrusion prevention framework
- [ddos-deflate](https://github.com/jgmdev/ddos-deflate) - Older DDoS protection script
- [CSF](https://configserver.com/cp/csf.html) - ConfigServer Security & Firewall

## Disclaimer

This tool is provided as-is for educational and practical use. It's designed for small-scale attacks and should not be considered a replacement for professional DDoS protection services for high-value targets or large-scale attacks.

