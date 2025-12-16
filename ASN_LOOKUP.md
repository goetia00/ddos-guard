# ASN (Autonomous System Number) Lookup Guide

DDoS Guard can identify the ISP, hosting provider, or organization behind attacking IPs using ASN lookup. This helps identify patterns and block entire malicious networks.

## Why ASN Information Matters

### Attack Pattern Analysis
- **Identify hosting providers**: "All attacks from Vultr" → block entire ASN
- **Cloud infrastructure abuse**: AWS/GCP/Azure IPs used in botnets
- **ISP patterns**: Residential ISPs vs. data centers
- **Known malicious ASNs**: Some ASNs are notorious for abuse

### Examples of ASN Data
```
AS15169 - GOOGLE (Google Cloud)
AS16509 - AMAZON-02 (AWS)
AS14061 - DIGITALOCEAN-ASN (DigitalOcean)
AS209605 - UAB-CHERRY-SERVERS (known for abuse)
AS8075 - MICROSOFT-CORP-MSN-AS-BLOCK (Azure)
```

## Configuration

### Option 1: MaxMind GeoLite2-ASN (Recommended)

**Pros:**
- ✅ Fast (local lookup, no API calls)
- ✅ No rate limits
- ✅ Free (GeoLite2-ASN.mmdb)
- ✅ Consistent with GeoIP approach
- ✅ Privacy-friendly (offline)

**Installation:**

```bash
# 1. Sign up for free MaxMind account
# Visit: https://www.maxmind.com/en/geolite2/signup

# 2. Configure geoipupdate
sudo tee /etc/GeoIP.conf << EOF
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City GeoLite2-Country GeoLite2-ASN
EOF

# 3. Download databases
sudo geoipupdate

# 4. Verify installation
ls -lh /usr/share/GeoIP/
# Should show: GeoLite2-ASN.mmdb

# 5. Test lookup
mmdblookup -f /usr/share/GeoIP/GeoLite2-ASN.mmdb -i 8.8.8.8 autonomous_system_number
# Output: 15169

mmdblookup -f /usr/share/GeoIP/GeoLite2-ASN.mmdb -i 8.8.8.8 autonomous_system_organization
# Output: "GOOGLE"
```

**Enable in config:**

```bash
# Edit /etc/ddos-guard/ddos-guard.conf
ENABLE_ASN_LOOKUP=true
ASN_DB_PATH="/usr/share/GeoIP/GeoLite2-ASN.mmdb"
ASN_LOOKUP_METHOD="mmdb"
```

### Option 2: Team Cymru (DNS-based)

**Pros:**
- ✅ No database required
- ✅ Always up-to-date
- ✅ Free

**Cons:**
- ❌ Requires DNS queries (network dependency)
- ❌ Slower than local lookup
- ❌ Rate limiting possible

**Installation:**

```bash
# No installation needed, just enable in config
# Edit /etc/ddos-guard/ddos-guard.conf
ENABLE_ASN_LOOKUP=true
ASN_LOOKUP_METHOD="cymru"

# Test lookup manually
dig +short TXT $(echo 8.8.8.8 | awk -F. '{print $4"."$3"."$2"."$1}').origin.asn.cymru.com
# Output: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
```

## Data Export Format

### Threat Intelligence Export

When ASN lookup is enabled, exported data includes:

```json
{
  "subnet": "192.0.2.0/24",
  "family": "IPv4",
  "first_seen": "1765553894",
  "country": "US",
  "asn": "AS15169",
  "as_name": "GOOGLE",
  "as_organization": "Google LLC"
}
```

### Prometheus Metrics

ASN labels are added to metrics:

```
ddos_guard_blocked_subnet_info{
  subnet="192.0.2.0/24",
  family="ipv4",
  country="US",
  city="San Francisco",
  latitude="37.7749",
  longitude="-122.4194",
  asn="AS15169",
  as_name="GOOGLE"
} 1
```

## Grafana Visualization

The dashboard includes ASN-specific panels:

### 1. Top Attacking ASNs (Bar Chart)
Shows which autonomous systems are sending the most attacks:
```
╔═══════════════════════════════════════╗
║  ▓▓▓▓▓▓▓▓▓▓▓ AS209605 - CHERRY (12) ║
║  ▓▓▓▓▓▓▓ AS15169 - GOOGLE (8)       ║
║  ▓▓▓▓ AS16509 - AMAZON-02 (5)       ║
╚═══════════════════════════════════════╝
```

### 2. ASN Table
Detailed table with clickable ASN links to BGP information:
```
┌─────────┬──────────────┬─────────┬────────────────┐
│ ASN     │ Organization │ Country │ Subnet         │
├─────────┼──────────────┼─────────┼────────────────┤
│ AS15169 │ GOOGLE       │ US      │ 8.8.8.0/24     │
│ AS209605│ CHERRY       │ LT      │ 5.2.64.0/24    │
└─────────┴──────────────┴─────────┴────────────────┘
```

### 3. ASN Distribution (Pie Chart)
Shows proportion of attacks by organization

### 4. Unique ASNs Blocked
Single stat showing count of distinct ASNs

## Use Cases

### 1. Block Entire Malicious ASNs

If you notice all attacks come from one ASN:

```bash
# Add to whitelist to prevent accidental blocks
echo "AS15169" >> /etc/ddos-guard/asn_whitelist.txt  # (Future feature)

# Or manually block at firewall level
sudo iptables -I INPUT -m comment --comment "Block AS209605" -j DROP
```

### 2. Identify Cloud Infrastructure Abuse

Monitor for attacks from major cloud providers:
```bash
# Check logs for cloud provider ASNs
sudo journalctl -u ddos-guard | grep -E "AS(15169|16509|14061|8075)"
```

### 3. Report Abuse to ISPs

Use ASN information to contact network operators:
```bash
# Look up ASN contact info
whois -h whois.cymru.com " -v AS15169"
# Find abuse email and report
```

### 4. Geographic + ASN Correlation

Identify region-specific hosting provider abuse:
```
Country: Lithuania
ASN: AS209605 (Cherry Servers)
Pattern: Multiple /24 subnets from same DC
Action: Block entire ASN
```

## Performance Considerations

### Local MMDB Lookup
- **Latency**: < 1ms per lookup
- **Caching**: Results cached in memory
- **Impact**: Minimal, adds ~0.5s per scan

### DNS-based (Cymru) Lookup
- **Latency**: 50-200ms per lookup
- **Caching**: Results cached in memory
- **Impact**: Moderate, adds ~2-5s per scan

**Recommendation**: Use MMDB method for production.

## Troubleshooting

### ASN shows "unknown"

1. **Check database exists:**
   ```bash
   ls -lh /usr/share/GeoIP/GeoLite2-ASN.mmdb
   ```

2. **Test mmdblookup:**
   ```bash
   mmdblookup -f /usr/share/GeoIP/GeoLite2-ASN.mmdb -i 8.8.8.8
   ```

3. **Check config:**
   ```bash
   grep ASN /etc/ddos-guard/ddos-guard.conf
   ```

4. **Restart service:**
   ```bash
   sudo systemctl restart ddos-guard
   ```

### Cymru DNS lookup failing

1. **Check DNS resolution:**
   ```bash
   dig +short TXT 8.8.8.8.origin.asn.cymru.com
   ```

2. **Firewall blocking DNS:**
   ```bash
   sudo iptables -L OUTPUT | grep -i dns
   ```

3. **Switch to MMDB method**

### Database out of date

MaxMind databases are updated weekly:

```bash
# Update manually
sudo geoipupdate

# Set up automatic updates (recommended)
sudo crontab -e
# Add: 0 2 * * 3 /usr/bin/geoipupdate
```

## Privacy Considerations

### What is Shared
When threat intelligence sharing is enabled with ASN lookup:
- ✅ ASN number (e.g., AS15169)
- ✅ Organization name (e.g., GOOGLE)

### What is NOT Shared
- ❌ Your server's ASN
- ❌ Your infrastructure details
- ❌ Lookup timestamps or frequency

## Command Reference

### View ASN data in exports
```bash
sudo cat /var/run/ddos-guard.intel_export.json | jq '.blocked_subnets[] | {subnet, asn, as_organization}'
```

### Count unique ASNs
```bash
sudo cat /var/run/ddos-guard.intel_export.json | jq -r '.blocked_subnets[].asn' | sort | uniq -c
```

### List top attacking ASNs
```bash
sudo cat /var/run/ddos-guard.intel_export.json | jq -r '.blocked_subnets[] | "\(.asn) - \(.as_name)"' | sort | uniq -c | sort -rn | head -10
```

### Check Prometheus metrics
```bash
curl -s http://localhost:9100/metrics | grep ddos_guard_blocked_subnet_info | grep asn
```

## FAQ

**Q: Do I need both GeoIP and ASN databases?**
A: No, they're independent. ASN identifies the network owner, GeoIP identifies location.

**Q: Will this slow down my server?**
A: Minimal impact with MMDB method. Lookups are cached and only done during scans.

**Q: Can I block by ASN directly?**
A: Not yet, but you can use the ASN data to manually block at firewall level.

**Q: How accurate is ASN data?**
A: Very accurate. ASN assignments are managed by regional internet registries (RIRs).

**Q: What if an IP has no ASN?**
A: Rare, but it will show as "unknown". Most internet-routable IPs have ASN assignments.

## Further Reading

- [What is an ASN?](https://www.cloudflare.com/learning/network-layer/what-is-an-autonomous-system/)
- [MaxMind GeoLite2 ASN](https://dev.maxmind.com/geoip/geoip2/geolite2/)
- [Team Cymru IP to ASN](https://www.team-cymru.com/ip-asn-mapping)
- [Hurricane Electric BGP Toolkit](https://bgp.he.net/)

