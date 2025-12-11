# DDoS Guard

Simple SYN flood detection and mitigation for Linux servers using iptables.

## Overview

DDoS Guard is a lightweight systemd service that monitors for SYN flood attacks and automatically blocks attacking IP subnets using iptables. It's designed for small to medium-scale attacks where blocking at the host level is sufficient.

## Features

- ✅ **Three detection modes** to reduce false positives:
  - **Age-based**: Only count stuck connections (ignores fast legitimate traffic)
  - **Rate-based**: Track connection rate over time windows
  - **Count-based**: Simple threshold (original behavior)
- ✅ **Per-IP rate limiting** to catch single-source attacks early
- ✅ **Enhanced logging** with detection reasons for each block
- ✅ Automatic SYN flood detection via `ss` command
- ✅ Configurable threshold and monitoring intervals
- ✅ Whitelist support for trusted IPs/subnets
- ✅ IPv4 and IPv6 support
- ✅ Multiple port monitoring
- ✅ Auto-unblock after configurable time period
- ✅ Systemd integration with proper logging
- ✅ Persistent iptables rules
- ✅ Zero dependencies beyond standard Linux tools (except optional `bc` for age parsing)

## When to Use

✅ **Good for:**
- Small-medium VPS under SYN flood attack
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
- `bc` (optional, for age-based detection timer parsing - usually pre-installed)

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

### Basic Settings

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

### Advanced Detection Settings (Reduce False Positives)

```bash
# Detection mode: "count", "age", or "rate"
DETECTION_MODE="age"

# Minimum connection age in seconds (for age mode)
# Only count SYN-RECV connections stuck for this long
MIN_CONNECTION_AGE=3

# Rate tracking window in seconds (for rate mode)
# Track connection rate over this time period
RATE_WINDOW=60

# Per-IP rate limit (connections per minute, 0 = disabled)
# Block IPs exceeding this rate regardless of subnet aggregation
PER_IP_RATE_LIMIT=30
```

### Detection Modes Explained

**🎯 Age Mode (Recommended for production)**
```bash
DETECTION_MODE="age"
MIN_CONNECTION_AGE=3
```
- Only counts SYN-RECV connections that have been stuck for >3 seconds
- **Why it works**: Legitimate connections complete in <1 second, attacks persist
- **Best for**: High-traffic sites where many users connect simultaneously
- **Trade-off**: Slightly slower to detect attacks (waits for connections to age)

**📊 Rate Mode (Best for detecting bursts)**
```bash
DETECTION_MODE="rate"
RATE_WINDOW=60
```
- Tracks how many **new** connections appear per time window
- **Why it works**: Measures connection rate, not just current snapshot
- **Best for**: Detecting sudden bursts from attackers
- **Trade-off**: Uses more memory to track historical data

**🔢 Count Mode (Original behavior)**
```bash
DETECTION_MODE="count"
```
- Blocks if current SYN-RECV count exceeds threshold
- **Why it works**: Simple and fast
- **Best for**: Low-traffic sites or obvious attacks
- **Trade-off**: Higher false positive risk on busy sites

**🚨 Per-IP Rate Limiting**
```bash
PER_IP_RATE_LIMIT=30  # connections per minute
```
- Blocks individual IPs creating too many connections
- Works across all detection modes
- Catches single-source attacks before subnet aggregation
- Set to 0 to disable

## Choosing the Right Settings

### For Small/Medium Sites (<100 concurrent users)
```bash
DETECTION_MODE="age"
MIN_CONNECTION_AGE=3
THRESHOLD=10
PER_IP_RATE_LIMIT=30
```

### For High-Traffic Sites (1000+ concurrent users)
```bash
DETECTION_MODE="age"
MIN_CONNECTION_AGE=5
THRESHOLD=50
PER_IP_RATE_LIMIT=50
```

### For Obvious Attacks (like the 138.121.x scenario)
```bash
DETECTION_MODE="count"  # Fast and simple
THRESHOLD=10
PER_IP_RATE_LIMIT=20
```

### For Sophisticated/Distributed Attacks
```bash
DETECTION_MODE="rate"
RATE_WINDOW=120
THRESHOLD=30
PER_IP_RATE_LIMIT=20
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

# CDN/Load balancer IPs
# (IMPORTANT: Add these to avoid blocking legitimate traffic)
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

### Understanding the Logs

**Example log output with new features:**
```
[2025-01-15 14:23:10] DDoS Guard started
[2025-01-15 14:23:10]   Detection Mode: age
[2025-01-15 14:23:10]   Threshold: 10 connections
[2025-01-15 14:23:10]   Min Connection Age: 3s (filters fast legitimate connections)
[2025-01-15 14:23:10]   Per-IP Rate Limit: 30 conn/min

[2025-01-15 14:23:40] Starting DDoS detection scan (mode: age, ports: 443)
[2025-01-15 14:23:40] Found 45 qualifying SYN-RECV connections older than 3s
[2025-01-15 14:23:40] WARNING: IP 138.121.245.42 exceeded rate limit: 35 conn/min (limit: 30)
[2025-01-15 14:23:40] BLOCKING [IPv4]: 138.121.245.0/24 - Per-IP rate limit exceeded: 35/min (15 connections)
[2025-01-15 14:23:40] Scan complete. Total subnets blocked: 1
```

**What each line means:**
- `Detection Mode: age` - Using age-based detection (smart filtering)
- `Found 45 qualifying SYN-RECV connections older than 3s` - Only counting stuck connections
- `Per-IP rate limit exceeded: 35/min` - Why the block happened (exceeded rate limit)
- `BLOCKING [IPv4]: 138.121.245.0/24` - Entire /24 subnet blocked

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

1. Every `CHECK_INTERVAL` seconds, the script scans for SYN-RECV connections
2. **Detection mode determines what to count**:
   - **Age mode**: Uses `ss -anto` to get timer info, filters connections <MIN_CONNECTION_AGE seconds
   - **Rate mode**: Tracks new connections in a sliding time window (RATE_WINDOW)
   - **Count mode**: Simple snapshot count of current SYN-RECV connections
3. **Per-IP rate limiting** (if enabled): Checks if any single IP exceeds connections/minute limit
4. **Subnet aggregation**: Groups IPs by subnet (default /24) to detect coordinated attacks
5. **Threshold check**: If subnet exceeds THRESHOLD, blocks the entire subnet via iptables
6. **Enhanced logging**: Records detection method and reason for each block
7. **Auto-unblock** (optional): Removes blocks after configured hours

### Why This Reduces False Positives

**The Problem with Simple Counting:**
- Legitimate traffic: User connects → SYN-RECV → ESTABLISHED (100ms)
- Attack traffic: Attacker SYNs → SYN-RECV → stuck forever
- 1000 legitimate users = brief spike of SYN-RECV, but they complete quickly
- 10 attack connections = persistent SYN-RECV that never complete

**How Age Mode Solves It:**
- Only counts connections stuck for >3 seconds
- Legitimate connections are long gone by then
- Attack connections accumulate and get caught

**How Rate Mode Solves It:**
- Tracks connection rate, not just current count
- Sudden burst of 100 connections/second = likely attack
- Steady 100 connections over 60 seconds = likely legitimate

## Improvements Over Original Version

### What Changed?

**Old approach (count mode)**:
- Counted all SYN-RECV connections in current snapshot
- Blocked if total exceeded threshold
- Risk: Legitimate high-traffic = false positives

**New approach (age/rate modes)**:
- **Age mode**: Only counts connections stuck >3 seconds (attacks persist, legitimate traffic completes)
- **Rate mode**: Tracks connection rate over time windows (detects bursts)
- **Per-IP limiting**: Catches single-source attacks early
- **Better logging**: Shows why each block happened

### Real-World Scenarios

**Scenario 1: 1000 legitimate users connect simultaneously**
- Old: Would see 1000 SYN-RECV → BLOCK (false positive!)
- New (age mode): Sees 1000 SYN-RECV, but they complete in <1s → No block ✅

**Scenario 2: SYN flood attack from 138.121.245.x**
- Old: Counts SYN-RECV → blocks at threshold
- New: Counts stuck connections + rate + per-IP → blocks faster with detailed reason ✅

**Scenario 3: Slow distributed attack (10 IPs, 5 conn each)**
- Old: 50 total connections spread across subnets → might miss it
- New (rate mode): Detects 50 connections in 60s window → blocks ✅

## Limitations

- **Bandwidth already consumed**: iptables blocks at host level, so traffic still hits your network interface
- **Not for volumetric attacks**: If your pipe is saturated, this won't help
- **Host-level only**: Can't protect against upstream saturation
- **Best for limited IP ranges**: Won't help if attack comes from 1000+ different subnets
- **Age mode requires accurate timers**: Works best on recent Linux kernels with good `ss` support

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

**Switch to age mode (recommended)**:
```bash
DETECTION_MODE="age"
MIN_CONNECTION_AGE=5  # Increase to be more conservative
THRESHOLD=20          # Increase threshold
```

**Other solutions**:
- Add legitimate IPs to whitelist (CDNs, load balancers, monitoring)
- Increase `THRESHOLD` value (try 50-100 for high-traffic sites)
- Increase `MIN_CONNECTION_AGE` to 5-10 seconds
- Disable `PER_IP_RATE_LIMIT` if it's too aggressive (set to 0)

### Attack not being detected

**Switch to count mode (more aggressive)**:
```bash
DETECTION_MODE="count"
THRESHOLD=5  # Lower threshold for faster blocking
```

**Other solutions**:
- Check logs: `sudo journalctl -u ddos-guard -f`
- Verify ports are correct in config
- Check if attacker IPs are whitelisted
- Lower `THRESHOLD` value
- In age mode, lower `MIN_CONNECTION_AGE` to 1-2 seconds

### Check current detection effectiveness

```bash
# See what would be detected without blocking (dry run)
sudo ss -anto | grep SYN-RECV | grep ':443'

# Count by source IP
sudo ss -ant | grep SYN-RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Check connection ages (shows timer info)
sudo ss -anto | grep SYN-RECV | grep ':443'
```

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

## Quick Reference

### Detection Modes at a Glance

| Mode | When to Use | False Positives | Detection Speed | Best For |
|------|------------|----------------|----------------|----------|
| **age** | High-traffic sites | ⭐⭐⭐ Low | Medium | Production sites |
| **rate** | Burst attacks | ⭐⭐ Medium | Medium | Sophisticated attacks |
| **count** | Obvious attacks | ⭐ High | Fast | Low-traffic or clear attacks |

### Configuration Templates

**Conservative (minimize false positives)**:
```bash
DETECTION_MODE="age"
MIN_CONNECTION_AGE=10
THRESHOLD=50
PER_IP_RATE_LIMIT=50
```

**Balanced (recommended starting point)**:
```bash
DETECTION_MODE="age"
MIN_CONNECTION_AGE=3
THRESHOLD=10
PER_IP_RATE_LIMIT=30
```

**Aggressive (maximum protection)**:
```bash
DETECTION_MODE="count"
THRESHOLD=5
PER_IP_RATE_LIMIT=15
CHECK_INTERVAL=15
```

### Common Commands

```bash
# View current config
cat /etc/ddos-guard/ddos-guard.conf

# View blocked subnets
cat /var/run/ddos-guard.state

# Manually unblock a subnet
sudo iptables -D INPUT -s 192.0.2.0/24 -j DROP
sudo sed -i '/192.0.2.0\/24/d' /var/run/ddos-guard.state

# Test detection (see what would be caught)
sudo ss -anto | grep SYN-RECV | grep ':443'

# Check service health
sudo systemctl status ddos-guard
sudo journalctl -u ddos-guard -n 50
```

## Disclaimer

This tool is provided as-is for educational and practical use. It's designed for small-scale attacks and should not be considered a replacement for professional DDoS protection services for high-value targets or large-scale attacks.

The new detection modes significantly reduce false positives, but you should always monitor the tool's behavior in your specific environment and adjust thresholds accordingly.

