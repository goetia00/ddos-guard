# Threat Intelligence Sharing Guide

DDoS Guard supports community threat intelligence sharing through a GitHub-based system. This allows users to share and benefit from collective defense against DDoS attacks.

## Overview

The threat intelligence system works by:
1. **Exporting** your blocked subnets to a JSON file
2. **Sharing** via a GitHub repository (manual or automated)
3. **Downloading** the community feed
4. **Applying** blocks from the community (optional)

## Step 1: Enable Threat Intelligence

Edit `/etc/ddos-guard/ddos-guard.conf`:

```bash
# Enable threat intelligence sharing
ENABLE_INTEL_SHARING=true

# Optional: Auto-block from community feed (be cautious!)
AUTO_BLOCK_FROM_FEED=false  # Set to true only if you trust the feed
```

Restart the service:
```bash
sudo systemctl restart ddos-guard
```

## Step 2: Export Your Blocked Subnets

DDoS Guard automatically exports blocked subnets to:
```
/var/run/ddos-guard.intel_export.json
```

**Example export format:**
```json
{
  "version": "1.0",
  "generated_at": "2025-12-12T16:00:00Z",
  "source": "ddos-guard",
  "blocked_subnets": [
    {
      "subnet": "192.0.2.0/24",
      "family": "IPv4",
      "first_seen": "1765553894",
      "country": "US",
      "asn": "AS15169",
      "as_name": "GOOGLE",
      "as_organization": "Google LLC"
    },
    {
      "subnet": "198.51.100.0/24",
      "family": "IPv4",
      "first_seen": "1765554000",
      "country": "CN",
      "asn": "AS4134",
      "as_name": "CHINANET",
      "as_organization": "Chinanet"
    }
  ]
}
```

**Note:** ASN fields are only included when `ENABLE_ASN_LOOKUP=true` in configuration. See [ASN_LOOKUP.md](ASN_LOOKUP.md) for setup.

## Step 3: Share with Community (Manual Method)

### Option A: Contribute to Official Repository

1. **Fork the threat-intel repository:**
   ```bash
   # Visit: https://github.com/ddos-guard/threat-intel
   # Click "Fork"
   ```

2. **Add your data:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/threat-intel.git
   cd threat-intel
   
   # Copy your export
   cp /var/run/ddos-guard.intel_export.json submissions/$(hostname)-$(date +%Y%m%d).json
   
   git add submissions/
   git commit -m "Add blocked subnets from $(hostname)"
   git push origin main
   ```

3. **Create Pull Request:**
   - Go to your fork on GitHub
   - Click "Pull Request"
   - Submit for review

### Option B: Automated Sharing (Advanced)

Create a cron job to periodically submit updates:

```bash
# /etc/cron.daily/ddos-guard-intel-share
#!/bin/bash
INTEL_FILE="/var/run/ddos-guard.intel_export.json"
REPO_PATH="/opt/threat-intel"

if [[ -f "$INTEL_FILE" ]] && [[ -d "$REPO_PATH" ]]; then
    cd "$REPO_PATH"
    git pull
    cp "$INTEL_FILE" "submissions/$(hostname)-$(date +%Y%m%d).json"
    git add submissions/
    git commit -m "Auto-update from $(hostname)"
    git push
fi
```

## Step 4: Download Community Feed

The tool automatically downloads the community feed on startup when enabled.

**Manual download:**
```bash
# Download feed
curl -o /var/run/ddos-guard.intel_feed.json \
  https://raw.githubusercontent.com/ddos-guard/threat-intel/main/blocked_subnets.json

# Or using the built-in function
sudo systemctl restart ddos-guard  # Downloads on startup
```

**Check downloaded feed:**
```bash
sudo cat /var/run/ddos-guard.intel_feed.json | jq .
```

## Step 5: Apply Community Blocks (Optional)

**Automatic (recommended for testing):**
```bash
# Edit config
sudo vim /etc/ddos-guard/ddos-guard.conf

# Set:
AUTO_BLOCK_FROM_FEED=true

# Restart
sudo systemctl restart ddos-guard
```

**Manual review before applying:**
```bash
# View feed
sudo cat /var/run/ddos-guard.intel_feed.json | jq '.blocked_subnets[] | .subnet'

# Manually add trusted subnets to your config
```

## Threat Intel Feed Structure

### Community Feed Format

The official feed aggregates submissions from multiple users:

```json
{
  "version": "1.0",
  "generated_at": "2025-12-12T16:00:00Z",
  "source": "ddos-guard-community",
  "statistics": {
    "total_subnets": 150,
    "contributors": 25,
    "countries": ["CN", "RU", "US", "KR"]
  },
  "blocked_subnets": [
    {
      "subnet": "192.0.2.0/24",
      "family": "IPv4",
      "first_seen": "1765553894",
      "last_seen": "1765560000",
      "reporters": 5,
      "country": "CN",
      "confidence": "high"
    }
  ]
}
```

### Confidence Levels

- **high**: Reported by 5+ independent sources
- **medium**: Reported by 2-4 sources
- **low**: Reported by 1 source

## Privacy Considerations

### What is Shared

When you enable intel sharing, the following information is exported:
- ✅ Blocked subnet (e.g., `192.0.2.0/24`)
- ✅ IP family (IPv4/IPv6)
- ✅ First seen timestamp
- ✅ Country (if GeoIP enabled)
- ✅ ASN and organization (if ASN lookup enabled)

### What is NOT Shared

- ❌ Your server IP or hostname
- ❌ Attack details or logs
- ❌ Your infrastructure information
- ❌ Whitelisted IPs
- ❌ Detection thresholds or configuration

### Anonymization

All submissions are anonymous. The community feed does not track which user submitted which subnet.

## Security Considerations

### Trust Model

**Enabling AUTO_BLOCK_FROM_FEED means:**
- You trust the community feed maintainers
- You trust the submission process
- You accept risk of false positives

**Recommendations:**
1. Start with `AUTO_BLOCK_FROM_FEED=false`
2. Review the feed manually
3. Whitelist your legitimate traffic sources
4. Gradually enable auto-blocking after testing

### Preventing False Positives

1. **Whitelist important IPs:**
   ```bash
   echo "YOUR_OFFICE_IP" >> /etc/ddos-guard/whitelist.txt
   echo "YOUR_CDN_RANGE/24" >> /etc/ddos-guard/whitelist.txt
   ```

2. **Monitor logs:**
   ```bash
   sudo journalctl -u ddos-guard -f | grep "threat intel"
   ```

3. **Use confidence levels (future feature):**
   Only auto-block "high" confidence entries

## Troubleshooting

### Export not generating

1. **Check if enabled:**
   ```bash
   grep ENABLE_INTEL_SHARING /etc/ddos-guard/ddos-guard.conf
   ```

2. **Check export file:**
   ```bash
   sudo cat /var/run/ddos-guard.intel_export.json
   ```

3. **Check permissions:**
   ```bash
   sudo ls -la /var/run/ddos-guard.intel_export.json
   ```

### Feed download failing

1. **Check network connectivity:**
   ```bash
   curl -I https://raw.githubusercontent.com/ddos-guard/threat-intel/main/blocked_subnets.json
   ```

2. **Check logs:**
   ```bash
   sudo journalctl -u ddos-guard | grep "threat intel"
   ```

3. **Verify curl/wget installed:**
   ```bash
   which curl wget
   ```

### Blocks not applying from feed

1. **Check AUTO_BLOCK_FROM_FEED:**
   ```bash
   grep AUTO_BLOCK_FROM_FEED /etc/ddos-guard/ddos-guard.conf
   ```

2. **Check feed file exists:**
   ```bash
   sudo ls -la /var/run/ddos-guard.intel_feed.json
   ```

3. **Manually test:**
   ```bash
   # Check if subnet would be blocked
   sudo iptables -L INPUT -v -n | grep "192.0.2.0/24"
   ```

## Command Reference

### View your exported intel
```bash
sudo cat /var/run/ddos-guard.intel_export.json | jq .
```

### View community feed
```bash
sudo cat /var/run/ddos-guard.intel_feed.json | jq .
```

### Count blocked subnets
```bash
jq '.blocked_subnets | length' /var/run/ddos-guard.intel_export.json
```

### List blocked countries
```bash
jq -r '.blocked_subnets[].country' /var/run/ddos-guard.intel_export.json | sort | uniq -c
```

### Force download feed
```bash
# Restart service (downloads on startup)
sudo systemctl restart ddos-guard
```

## Contributing to the Community

### Guidelines for Submissions

1. **Only submit verified attacks:**
   - Don't submit legitimate traffic
   - Verify attacks using logs
   - Check whitelists first

2. **Include accurate GeoIP data:**
   - Enable GeoIP before submitting
   - Helps community identify attack patterns

3. **Regular updates:**
   - Submit updates weekly or when significant changes occur
   - Remove old/stale entries

### Creating Your Own Feed

Instead of using the official feed, you can create a private feed:

1. **Create private repository:**
   ```bash
   # On GitHub, create private repo: your-org/ddos-intel
   ```

2. **Update config:**
   ```bash
   INTEL_FEED_URL="https://raw.githubusercontent.com/your-org/ddos-intel/main/feed.json"
   ```

3. **Share with trusted partners only**

## Roadmap

Future enhancements:
- ✅ Basic GitHub-based sharing (implemented)
- 🔄 Confidence scoring based on reporter count
- 🔄 Automatic feed aggregation from multiple sources
- 🔄 Signature-based verification of submissions
- 🔄 Real-time API for instant updates
- 🔄 Integration with other threat feeds (AbuseIPDB, etc.)

## FAQ

**Q: Will this block legitimate users?**
A: Only if they're in the community feed. Always use whitelists for your legitimate traffic.

**Q: How often is the feed updated?**
A: Community submissions are aggregated daily. Auto-updates happen on service restart.

**Q: Can I contribute anonymously?**
A: Yes. Submissions don't include your identity or server info.

**Q: What if I block a legitimate subnet?**
A: Add it to your whitelist immediately. Consider reporting false positives.

**Q: How do I opt out?**
A: Set `ENABLE_INTEL_SHARING=false` in config.

## Support

- GitHub Issues: https://github.com/goetia00/ddos-guard/issues
- Community feed repo: https://github.com/ddos-guard/threat-intel (when available)

