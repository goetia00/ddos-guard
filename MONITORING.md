# Monitoring Setup Guide

This guide explains how to set up Prometheus and Grafana to visualize DDoS Guard metrics, including geographic attack origin mapping.

## Overview

DDoS Guard can export Prometheus metrics that include:
- Total blocked subnets (IPv4/IPv6)
- Individual blocked subnet information
- Geographic data (country, city, coordinates) when GeoIP is enabled
- Detection statistics

## Prerequisites

- `node_exporter` installed and running
- Prometheus server (optional, for long-term storage)
- Grafana (for visualization)
- MaxMind GeoLite2 database (optional, for geographic data)

## Step 1: Enable Metrics in DDoS Guard

Edit `/etc/ddos-guard/ddos-guard.conf`:

```bash
# Enable metrics export
ENABLE_METRICS=true

# Optional: Enable GeoIP for geographic visualization
ENABLE_GEOIP=true
GEOIP_DB_PATH="/usr/share/GeoIP/GeoLite2-City.mmdb"
```

Restart the service:
```bash
sudo systemctl restart ddos-guard
```

## Step 2: Install and Configure node_exporter

### Install node_exporter

**Debian/Ubuntu:**
```bash
# Download latest release
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvfz node_exporter-1.7.0.linux-amd64.tar.gz
sudo cp node_exporter-1.7.0.linux-amd64/node_exporter /usr/local/bin/
sudo useradd --no-create-home --shell /bin/false node_exporter
sudo chown node_exporter:node_exporter /usr/local/bin/node_exporter
```

**Create systemd service** (`/etc/systemd/system/node_exporter.service`):
```ini
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
    --collector.textfile.directory=/var/lib/node_exporter/textfile_collector \
    --collector.textfile

[Install]
WantedBy=multi-user.target
```

**Create metrics directory:**
```bash
sudo mkdir -p /var/lib/node_exporter/textfile_collector
sudo chown node_exporter:node_exporter /var/lib/node_exporter/textfile_collector
```

**Start node_exporter:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter
```

## Step 3: Install MaxMind GeoLite2 (Optional)

For geographic visualization, download the free GeoLite2 database:

```bash
# Create directory
sudo mkdir -p /usr/share/GeoIP

# Download GeoLite2 City database (requires free MaxMind account)
# Visit: https://dev.maxmind.com/geoip/geoip2/geolite2/
# Download GeoLite2-City.mmdb and place in /usr/share/GeoIP/

# Or use automated download (requires license key):
# wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz" -O GeoLite2-City.tar.gz
# tar xzf GeoLite2-City.tar.gz
# sudo cp GeoLite2-City_*/GeoLite2-City.mmdb /usr/share/GeoIP/

# Install mmdblookup tool
sudo apt install libmaxminddb0 libmaxminddb-dev mmdb-bin  # Debian/Ubuntu
# OR
sudo yum install libmaxminddb libmaxminddb-devel  # RHEL/CentOS
```

## Step 4: Configure Prometheus (Optional)

If you want to scrape metrics with Prometheus:

**Edit `prometheus.yml`:**
```yaml
scrape_configs:
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:9100']
```

The metrics will be available at: `http://localhost:9100/metrics`

## Step 5: Import Grafana Dashboard

1. **Install Grafana:**
```bash
# Debian/Ubuntu
sudo apt install grafana
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

2. **Add Prometheus data source:**
   - Open Grafana: http://localhost:3000
   - Go to Configuration → Data Sources
   - Add Prometheus
   - URL: `http://localhost:9090` (if using Prometheus) or use node_exporter directly

3. **Import dashboard:**
   - Go to Dashboards → Import
   - Upload `grafana-dashboard.json` from this repository
   - Or use dashboard ID (if published to grafana.com)

## Step 6: Verify Metrics

Check that metrics are being exported:

```bash
# View metrics file
sudo cat /var/lib/node_exporter/textfile_collector/ddos_guard.prom

# Or query via node_exporter
curl http://localhost:9100/metrics | grep ddos_guard
```

Expected output:
```
# HELP ddos_guard_blocked_subnets_total Total number of subnets currently blocked
# TYPE ddos_guard_blocked_subnets_total gauge
ddos_guard_blocked_subnets_total{family="all"} 52
ddos_guard_blocked_subnets_total{family="ipv4"} 50
ddos_guard_blocked_subnets_total{family="ipv6"} 2

# HELP ddos_guard_blocked_subnet_info Information about blocked subnets
# TYPE ddos_guard_blocked_subnet_info gauge
ddos_guard_blocked_subnet_info{subnet="192.0.2.0/24",family="ipv4",country="US",city="New York",latitude="40.7128",longitude="-74.0060"} 1
```

## Troubleshooting

### Metrics not appearing

1. **Check metrics file exists:**
   ```bash
   sudo ls -la /var/lib/node_exporter/textfile_collector/ddos_guard.prom
   ```

2. **Check file permissions:**
   ```bash
   sudo chmod 644 /var/lib/node_exporter/textfile_collector/ddos_guard.prom
   sudo chown node_exporter:node_exporter /var/lib/node_exporter/textfile_collector/ddos_guard.prom
   ```

3. **Check node_exporter logs:**
   ```bash
   sudo journalctl -u node_exporter -f
   ```

4. **Verify DDoS Guard is exporting:**
   ```bash
   sudo journalctl -u ddos-guard | grep -i metric
   ```

### GeoIP not working

1. **Check database exists:**
   ```bash
   sudo ls -la /usr/share/GeoIP/GeoLite2-City.mmdb
   ```

2. **Test mmdblookup:**
   ```bash
   mmdblookup -f /usr/share/GeoIP/GeoLite2-City.mmdb -i 8.8.8.8
   ```

3. **Check cache file:**
   ```bash
   sudo cat /var/run/ddos-guard.geoip_cache
   ```

## Metrics Reference

### `ddos_guard_blocked_subnets_total`
- **Type:** Gauge
- **Labels:** `family` (all, ipv4, ipv6)
- **Description:** Total number of subnets currently blocked

### `ddos_guard_blocked_subnet_info`
- **Type:** Gauge
- **Labels:** 
  - `subnet` - Blocked subnet (e.g., "192.0.2.0/24")
  - `family` - IP family (ipv4, ipv6)
  - `country` - Country code (requires GeoIP)
  - `city` - City name (requires GeoIP)
  - `latitude` - Latitude (requires GeoIP)
  - `longitude` - Longitude (requires GeoIP)
- **Description:** Information about each blocked subnet (value is always 1 if blocked)

## Performance Considerations

- **GeoIP lookups:** Cached in `/var/run/ddos-guard.geoip_cache` to minimize overhead
- **Metrics file:** Written atomically to avoid corruption
- **Update frequency:** Metrics updated on each block and scan completion

## Next Steps

- Set up alerting in Grafana for high block counts
- Create custom dashboards for your specific needs
- Integrate with other monitoring tools
- Set up threat intelligence sharing (see roadmap)

