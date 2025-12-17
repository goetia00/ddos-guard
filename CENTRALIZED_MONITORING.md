# Centralized Monitoring Setup Guide

This guide shows how to set up a central Prometheus + Grafana server to monitor multiple DDoS Guard instances across different servers.

## Architecture Overview

```
┌─────────────────────┐         ┌─────────────────────┐
│  Server 1           │         │  Server 2           │
│  (Protected Host)   │         │  (Protected Host)   │
│                     │         │                     │
│  ┌──────────────┐   │         │  ┌──────────────┐   │
│  │ ddos-guard   │   │         │  │ ddos-guard   │   │
│  │ (metrics)    │   │         │  │ (metrics)    │   │
│  └──────┬───────┘   │         │  └──────┬───────┘   │
│         │           │         │         │           │
│  ┌──────▼───────┐   │         │  ┌──────▼───────┐   │
│  │node_exporter │   │         │  │node_exporter │   │
│  │ :9100        │   │         │  │ :9100        │   │
│  └──────────────┘   │         │  └──────────────┘   │
└──────────┬──────────┘         └──────────┬──────────┘
           │                               │
           │ HTTP :9100                    │ HTTP :9100
           │ (metrics scrape)              │ (metrics scrape)
           │                               │
           └───────────┬───────────────────┘
                       │
                       ▼
           ┌───────────────────────┐
           │  Central Monitoring   │
           │  Server (Linode)      │
           │                       │
           │  ┌─────────────────┐  │
           │  │  Prometheus     │  │
           │  │  :9090          │  │
           │  │  (scrapes)      │  │
           │  └────────┬────────┘  │
           │           │           │
           │  ┌────────▼────────┐  │
           │  │  Grafana        │  │
           │  │  :3000          │  │
           │  │  (visualizes)   │  │
           │  └─────────────────┘  │
           └───────────────────────┘
```

## Benefits

- ✅ **Centralized visualization** - One dashboard for all servers
- ✅ **Historical data** - Long-term storage and trending
- ✅ **Alerting** - Prometheus Alertmanager for notifications
- ✅ **Reduced resource usage** - Protected servers only run node_exporter
- ✅ **Easy scaling** - Add new servers by updating Prometheus config

---

## Part 1: Setup on Protected Servers (DDoS Guard Hosts)

These are your servers running ddos-guard that you want to monitor.

### Step 1: Enable Metrics in DDoS Guard

On **each protected server**, edit `/etc/ddos-guard/ddos-guard.conf`:

```bash
# Enable metrics export
ENABLE_METRICS=true
METRICS_FILE="/var/lib/node_exporter/textfile_collector/ddos_guard.prom"

# Enable GeoIP and ASN for enhanced data
ENABLE_GEOIP=true
ENABLE_ASN_LOOKUP=true
```

Restart ddos-guard:
```bash
sudo systemctl restart ddos-guard
```

### Step 2: Install node_exporter

On **each protected server**:

```bash
# Download node_exporter (latest version)
cd /tmp
wget https://github.com/prometheus/node_exporter/releases/download/v1.10.2/node_exporter-1.10.2.linux-amd64.tar.gz
tar xvfz node_exporter-1.10.2.linux-amd64.tar.gz
sudo cp node_exporter-1.10.2.linux-amd64/node_exporter /usr/local/bin/

# Create user
sudo useradd -rs /bin/false node_exporter

# Create textfile collector directory
sudo mkdir -p /var/lib/node_exporter/textfile_collector
sudo chown -R node_exporter:node_exporter /var/lib/node_exporter
```

### Step 3: Create node_exporter systemd service

```bash
sudo tee /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
  --collector.textfile.directory=/var/lib/node_exporter/textfile_collector \
  --web.listen-address=0.0.0.0:9100

# Security hardening
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ReadWritePaths=/var/lib/node_exporter

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter
sudo systemctl status node_exporter
```

### Step 4: Configure Firewall

**Important:** Only allow your monitoring server to access port 9100.

```bash
# Get your monitoring server IP
MONITORING_SERVER_IP="198.51.100.50"  # Replace with your Linode IP

# Allow only monitoring server to access node_exporter
sudo iptables -A INPUT -p tcp -s ${MONITORING_SERVER_IP} --dport 9100 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9100 -j DROP

# Save rules (Debian/Ubuntu)
sudo netfilter-persistent save

# Or for CentOS/RHEL
sudo service iptables save
```

**Alternative: Use Linode firewall (recommended)**

In Linode Cloud Manager:
1. Go to "Firewalls"
2. Create rule: Allow TCP port 9100 from monitoring server IP only

### Step 5: Test Metrics Endpoint

```bash
# From protected server (should work)
curl http://localhost:9100/metrics | grep ddos_guard

# From monitoring server (should work)
curl http://PROTECTED_SERVER_IP:9100/metrics | grep ddos_guard
```

---

## Part 2: Setup on Central Monitoring Server (Linode)

This is your centralized Prometheus + Grafana server.

### Step 1: Create Linode Instance

**Recommended specs:**
- **Linode 2GB** - Good for monitoring 5-10 servers
- **Linode 4GB** - Good for monitoring 10-50 servers
- **OS**: Ubuntu 22.04 LTS or Debian 12

### Step 2: Install Prometheus

```bash
# Create Prometheus user
sudo useradd --no-create-home --shell /bin/false prometheus

# Create directories
sudo mkdir /etc/prometheus
sudo mkdir /var/lib/prometheus
sudo chown prometheus:prometheus /var/lib/prometheus

# Download Prometheus (latest version)
cd /tmp
wget https://github.com/prometheus/prometheus/releases/download/v3.8.1/prometheus-3.8.1.linux-amd64.tar.gz
tar xvfz prometheus-3.8.1.linux-amd64.tar.gz

# Install binaries
sudo cp prometheus-3.8.1.linux-amd64/prometheus /usr/local/bin/
sudo cp prometheus-3.8.1.linux-amd64/promtool /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/prometheus
sudo chown prometheus:prometheus /usr/local/bin/promtool

# Copy console files
sudo cp -r prometheus-3.8.1.linux-amd64/consoles /etc/prometheus
sudo cp -r prometheus-3.8.1.linux-amd64/console_libraries /etc/prometheus
sudo chown -R prometheus:prometheus /etc/prometheus
```

### Step 3: Configure Prometheus

Create `/etc/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 30s
  evaluation_interval: 30s
  external_labels:
    monitor: 'ddos-guard-monitoring'

# Scrape configurations
scrape_configs:
  # Job for server 1
  - job_name: 'ddos-guard-server1'
    static_configs:
      - targets: ['192.0.2.10:9100']  # Replace with server 1 IP
        labels:
          server: 'server1'
          role: 'webserver'
          location: 'us-east'
  
  # Job for server 2
  - job_name: 'ddos-guard-server2'
    static_configs:
      - targets: ['192.0.2.11:9100']  # Replace with server 2 IP
        labels:
          server: 'server2'
          role: 'webserver'
          location: 'eu-west'
  
  # Job for server 3
  - job_name: 'ddos-guard-server3'
    static_configs:
      - targets: ['192.0.2.12:9100']  # Replace with server 3 IP
        labels:
          server: 'server3'
          role: 'database'
          location: 'ap-south'
  
  # Self-monitoring (optional)
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

**For many servers, use file-based service discovery:**

```yaml
scrape_configs:
  - job_name: 'ddos-guard-fleet'
    file_sd_configs:
      - files:
          - '/etc/prometheus/targets/*.yml'
        refresh_interval: 5m
```

Then create `/etc/prometheus/targets/servers.yml`:

```yaml
- targets:
    - '192.0.2.10:9100'
    - '192.0.2.11:9100'
    - '192.0.2.12:9100'
  labels:
    job: 'ddos-guard'
    environment: 'production'

- targets:
    - '192.0.2.20:9100'
    - '192.0.2.21:9100'
  labels:
    job: 'ddos-guard'
    environment: 'staging'
```

Set ownership:
```bash
sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml
sudo mkdir -p /etc/prometheus/targets
sudo chown -R prometheus:prometheus /etc/prometheus/targets
```

### Step 4: Create Prometheus systemd service

```bash
sudo tee /etc/systemd/system/prometheus.service << 'EOF'
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus/ \
  --web.console.templates=/etc/prometheus/consoles \
  --web.console.libraries=/etc/prometheus/console_libraries \
  --web.listen-address=0.0.0.0:9090 \
  --storage.tsdb.retention.time=30d

Restart=always

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable prometheus
sudo systemctl start prometheus
sudo systemctl status prometheus
```

### Step 5: Install Grafana

```bash
# Add Grafana repository
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -

# Install Grafana
sudo apt-get update
sudo apt-get install grafana

# Enable and start
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
sudo systemctl status grafana-server
```

### Step 6: Configure Grafana Data Source

1. **Access Grafana:**
   ```
   http://YOUR_MONITORING_SERVER_IP:3000
   ```
   Default login: `admin` / `admin`

2. **Add Prometheus data source:**
   - Go to: Configuration → Data Sources → Add data source
   - Select: Prometheus
   - URL: `http://localhost:9090`
   - Save & Test

3. **Import DDoS Guard dashboard:**
   - Go to: Create → Import
   - Upload: `/path/to/grafana-dashboard.json`
   - Select Prometheus data source
   - Import

### Step 7: Configure Firewall on Monitoring Server

```bash
# Allow Grafana (3000) from your office IP only
OFFICE_IP="203.0.113.50"  # Replace with your IP
sudo ufw allow from ${OFFICE_IP} to any port 3000

# Or allow from anywhere (less secure)
sudo ufw allow 3000/tcp

# Prometheus web UI (optional, for troubleshooting)
sudo ufw allow from ${OFFICE_IP} to any port 9090

# Enable firewall
sudo ufw enable
```

---

## Part 3: Advanced Configuration

### Multi-Environment Setup

For staging, production, etc.:

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'production'
    file_sd_configs:
      - files:
          - '/etc/prometheus/targets/production/*.yml'
    relabel_configs:
      - source_labels: [__address__]
        target_label: environment
        replacement: 'production'

  - job_name: 'staging'
    file_sd_configs:
      - files:
          - '/etc/prometheus/targets/staging/*.yml'
    relabel_configs:
      - source_labels: [__address__]
        target_label: environment
        replacement: 'staging'
```

### Authentication for node_exporter (Optional)

Use nginx as reverse proxy with basic auth:

```bash
# On protected server
sudo apt install nginx apache2-utils

# Create password
sudo htpasswd -c /etc/nginx/.htpasswd prometheus

# Configure nginx
sudo tee /etc/nginx/sites-available/node_exporter << 'EOF'
server {
    listen 9100;
    location /metrics {
        proxy_pass http://localhost:9101;  # node_exporter on different port
        auth_basic "Metrics";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/node_exporter /etc/nginx/sites-enabled/
sudo systemctl reload nginx

# Update node_exporter to listen on 9101
sudo systemctl edit node_exporter
# Add: --web.listen-address=127.0.0.1:9101
```

Update Prometheus config:
```yaml
scrape_configs:
  - job_name: 'ddos-guard-secure'
    basic_auth:
      username: 'prometheus'
      password: 'YOUR_PASSWORD'
    static_configs:
      - targets: ['192.0.2.10:9100']
```

### VPN/Tailscale Setup (Most Secure)

Instead of exposing port 9100, use Tailscale:

```bash
# On all servers
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Get Tailscale IP
tailscale ip -4

# Update Prometheus config to use Tailscale IPs
# Example: 100.64.0.10:9100
```

### Grafana Multi-Tenant Setup

Create separate organizations for different teams:

```bash
# Grafana CLI
grafana-cli admin reset-admin-password newpassword

# Create organizations via UI
# Settings → Organizations → New Organization
```

---

## Part 4: Grafana Dashboard Enhancements

### Server Selector Variable

Add a variable to filter by server:

```json
{
  "templating": {
    "list": [
      {
        "name": "server",
        "type": "query",
        "datasource": "Prometheus",
        "query": "label_values(ddos_guard_blocked_subnets_total, job)",
        "multi": true,
        "includeAll": true
      }
    ]
  }
}
```

Update panel queries:
```promql
ddos_guard_blocked_subnets_total{job=~"$server"}
```

### Aggregated View Across All Servers

```promql
# Total blocked subnets across all servers
sum(ddos_guard_blocked_subnets_total{family="all"})

# Top countries across all servers
topk(10, sum by (country) (ddos_guard_blocked_subnet_info))

# Servers under attack (SYN-RECV > 100)
count(ddos_guard_syn_recv_connections > 100)
```

---

## Part 5: Alerting Setup

### Configure Alertmanager

```bash
# Install Alertmanager
cd /tmp
wget https://github.com/prometheus/alertmanager/releases/download/v0.26.0/alertmanager-0.26.0.linux-amd64.tar.gz
tar xvfz alertmanager-0.26.0.linux-amd64.tar.gz
sudo cp alertmanager-0.26.0.linux-amd64/alertmanager /usr/local/bin/

# Create config
sudo mkdir /etc/alertmanager
sudo tee /etc/alertmanager/alertmanager.yml << 'EOF'
global:
  resolve_timeout: 5m

route:
  receiver: 'email-alerts'
  group_by: ['alertname', 'server']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h

receivers:
  - name: 'email-alerts'
    email_configs:
      - to: 'admin@example.com'
        from: 'alerts@example.com'
        smarthost: 'smtp.gmail.com:587'
        auth_username: 'alerts@example.com'
        auth_password: 'YOUR_APP_PASSWORD'
EOF
```

### Create Alert Rules

```bash
sudo tee /etc/prometheus/alert_rules.yml << 'EOF'
groups:
  - name: ddos_guard_alerts
    interval: 30s
    rules:
      # Alert when many subnets are blocked
      - alert: HighBlockedSubnets
        expr: ddos_guard_blocked_subnets_total{family="all"} > 50
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High number of blocked subnets on {{ $labels.server }}"
          description: "{{ $labels.server }} has {{ $value }} blocked subnets"
      
      # Alert on active SYN flood
      - alert: ActiveSYNFlood
        expr: ddos_guard_syn_recv_connections > 100
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Active SYN flood on {{ $labels.server }}"
          description: "{{ $value }} SYN-RECV connections detected"
      
      # Alert when node_exporter is down
      - alert: NodeExporterDown
        expr: up{job=~"ddos-guard.*"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Node exporter down on {{ $labels.server }}"
          description: "Cannot scrape metrics from {{ $labels.instance }}"
EOF
```

Update Prometheus config:
```yaml
# Add to prometheus.yml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - '/etc/prometheus/alert_rules.yml'
```

---

## Part 6: Backup and Disaster Recovery

### Backup Grafana Dashboards

```bash
# Automated backup script
sudo tee /usr/local/bin/grafana-backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups/grafana"
DATE=$(date +%Y%m%d-%H%M%S)
mkdir -p $BACKUP_DIR

# Backup dashboards via API
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3000/api/search?type=dash-db | \
  jq -r '.[] | .uid' | while read uid; do
    curl -H "Authorization: Bearer YOUR_API_KEY" \
      "http://localhost:3000/api/dashboards/uid/$uid" > \
      "$BACKUP_DIR/dashboard-$uid-$DATE.json"
  done
EOF

chmod +x /usr/local/bin/grafana-backup.sh

# Run daily
echo "0 2 * * * /usr/local/bin/grafana-backup.sh" | sudo crontab -
```

### Backup Prometheus Data

```bash
# Snapshot Prometheus data
curl -XPOST http://localhost:9090/api/v1/admin/tsdb/snapshot

# Or use rsync to backup /var/lib/prometheus
rsync -avz /var/lib/prometheus/ backup-server:/backups/prometheus/
```

---

## Troubleshooting

### Prometheus can't scrape targets

```bash
# Check connectivity from monitoring server
telnet PROTECTED_SERVER_IP 9100

# Check firewall on protected server
sudo iptables -L INPUT -v -n | grep 9100

# Check Prometheus logs
sudo journalctl -u prometheus -f

# Check targets in Prometheus UI
# http://MONITORING_SERVER_IP:9090/targets
```

### Missing metrics

```bash
# Check ddos-guard metrics file
cat /var/lib/node_exporter/textfile_collector/ddos_guard.prom

# Check node_exporter is collecting textfiles
curl http://localhost:9100/metrics | grep ddos_guard

# Check ddos-guard is running
sudo systemctl status ddos-guard
```

### Grafana shows "No data"

1. Check Prometheus data source connection
2. Verify metrics exist in Prometheus: http://MONITORING_SERVER:9090/graph
3. Check time range in Grafana dashboard
4. Verify query syntax

---

## Cost Optimization

### Prometheus Data Retention

Adjust retention to save disk space:
```bash
# In prometheus.service
--storage.tsdb.retention.time=15d  # Instead of 30d
--storage.tsdb.retention.size=10GB # Limit size
```

### Reduce Scrape Frequency

For less critical metrics:
```yaml
scrape_configs:
  - job_name: 'ddos-guard'
    scrape_interval: 60s  # Instead of 30s
```

### Use Prometheus Federation

For very large deployments, use hierarchical Prometheus:
```yaml
# Regional Prometheus scrapes local servers
# Central Prometheus federates from regional ones
```

---

## Recommended Linode Specs

| Servers Monitored | Linode Plan | CPU | RAM | Storage |
|-------------------|-------------|-----|-----|---------|
| 1-5               | Linode 2GB  | 1   | 2GB | 50GB    |
| 5-20              | Linode 4GB  | 2   | 4GB | 80GB    |
| 20-50             | Linode 8GB  | 4   | 8GB | 160GB   |
| 50+               | Linode 16GB | 6   | 16GB| 320GB   |

**Storage grows with retention period and scrape frequency.**

---

## Next Steps

1. ✅ Set up monitoring server (Linode)
2. ✅ Install Prometheus + Grafana
3. ✅ Configure each protected server with node_exporter
4. ✅ Add targets to Prometheus config
5. ✅ Import Grafana dashboard
6. ✅ Set up alerting
7. ✅ Configure backups
8. ✅ Test failover scenarios

For support, see the main [MONITORING.md](MONITORING.md) guide.

