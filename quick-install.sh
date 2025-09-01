#!/bin/bash
# IES Military Database Analyzer - Quick Installer for Proxmox
# Author - DXCSithlordPadawan
# One-line deployment: curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install.sh | bash

set -e

# Default configuration - easily modified
CT_ID="${CT_ID:-351}"
CT_NAME="${CT_NAME:-ies-analyzer}"
IP="${IP:-192.168.0.200}"
GATEWAY="${GATEWAY:-192.168.0.1}"
DNS="${DNS:-192.168.0.110}"
STORAGE="${STORAGE:-local-lvm}"
PASSWORD="${PASSWORD:-BobTheBigRedBus-0}"
CERT_SERVER="${CERT_SERVER:-192.168.0.122}"
DOMAIN="${DOMAIN:-ies-analyzer.local}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

msg_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
msg_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
msg_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
msg_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running on Proxmox
if ! command -v pct &> /dev/null; then
    msg_error "This script must be run on a Proxmox VE host"
    exit 1
fi

msg_info "Starting IES Military Database Analyzer Quick Installation"
msg_info "Container ID: $CT_ID | IP: $IP | Domain: $DOMAIN"

# Check if container ID exists
if pct status $CT_ID >/dev/null 2>&1; then
    msg_error "Container ID $CT_ID already exists!"
    msg_info "Use: export CT_ID=XXX before running to specify different ID"
    exit 1
fi

# Download Ubuntu template if needed
msg_info "Checking for Ubuntu 22.04 template..."
TEMPLATE="ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
if [[ ! -f "/var/lib/vz/template/cache/$TEMPLATE" ]]; then
    msg_info "Downloading Ubuntu 22.04 template..."
    pveam update >/dev/null 2>&1
    pveam download local $TEMPLATE
fi

# Create container
msg_info "Creating LXC container..."
pct create $CT_ID /var/lib/vz/template/cache/$TEMPLATE \
    --hostname "$CT_NAME" \
    --memory 2048 \
    --cores 2 \
    --rootfs "$STORAGE:8" \
    --net0 name=eth0,bridge=vmbr0,ip="$IP/24",gw="$GATEWAY" \
    --nameserver "$DNS" \
    --timezone "UTC" \
    --password "$PASSWORD" \
    --features nesting=1 \
    --unprivileged 1 \
    --onboot 1 \
    --start 1 >/dev/null 2>&1

msg_ok "Container $CT_ID created successfully"

# Wait for container to be ready
msg_info "Waiting for container to be ready..."
sleep 15

# Wait for network
retry_count=0
while ! pct exec $CT_ID -- ping -c 1 8.8.8.8 >/dev/null 2>&1; do
    if [[ $retry_count -ge 30 ]]; then
        msg_error "Network not ready after 30 attempts"
        exit 1
    fi
    sleep 2
    ((retry_count++))
done

msg_ok "Network connectivity established"

# Install everything in one go
msg_info "Installing and configuring IES application (this may take several minutes)..."

pct exec $CT_ID -- bash -c "
# Update system
apt-get update >/dev/null 2>&1
apt-get upgrade -y >/dev/null 2>&1

# Install system packages
apt-get install -y \
    curl wget git python3 python3-pip python3-venv \
    nginx supervisor ufw fail2ban htop nano vim unzip \
    ca-certificates gnupg lsb-release software-properties-common \
    openssh-server >/dev/null 2>&1

# Install Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo 'deb [arch=\$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable' > /etc/apt/sources.list.d/docker.list
apt-get update >/dev/null 2>&1
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
systemctl enable docker >/dev/null 2>&1
systemctl start docker >/dev/null 2>&1

# Clone IES repository
cd /opt
git clone https://github.com/DXCSithlordPadawan/IES.git >/dev/null 2>&1
cd IES

# Setup Python environment
python3 -m venv ies_env
source ies_env/bin/activate
pip install --upgrade pip >/dev/null 2>&1

# Install dependencies
if [ -f requirements.txt ]; then
    pip install -r requirements.txt >/dev/null 2>&1
else
    pip install flask pandas numpy matplotlib seaborn plotly networkx \\
               scikit-learn jinja2 gunicorn prometheus-client psutil >/dev/null 2>&1
fi

# Create directories
mkdir -p /opt/IES/{logs,data,config,static,templates}
chmod 755 /opt/IES/{logs,data,config}

# Create systemd service
cat > /etc/systemd/system/ies-analyzer.service << 'EOF'
[Unit]
Description=IES Military Database Analyzer
After=network.target

[Service]
Type=exec
User=root
WorkingDirectory=/opt/IES
Environment=PATH=/opt/IES/ies_env/bin
ExecStart=/opt/IES/ies_env/bin/python military_database_analyzer_v3.py --web --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-available/ies-analyzer << 'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;
    
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection \"1; mode=block\";
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        allow 192.168.0.0/24;
        allow 127.0.0.1;
        deny all;
    }
    
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        access_log off;
    }
    
    location /metrics {
        proxy_pass http://127.0.0.1:8000/metrics;
        allow 192.168.0.0/24;
        allow 127.0.0.1;
        deny all;
    }
}
EOF

# Generate SSL certificate
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
    -keyout /etc/nginx/ssl/server.key \\
    -out /etc/nginx/ssl/server.crt \\
    -subj '/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN' >/dev/null 2>&1

ln -sf /etc/nginx/sites-available/ies-analyzer /etc/nginx/sites-enabled/

# Setup monitoring
mkdir -p /opt/monitoring/{prometheus,grafana}
cat > /opt/monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ies-application'
    static_configs:
      - targets: ['$IP:8000']
    scrape_interval: 10s
    metrics_path: /metrics

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
EOF

cat > /opt/monitoring/docker-compose.yml << 'EOF'
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports: ['9090:9090']
    volumes:
      - ./prometheus:/etc/prometheus:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports: ['3000:3000']
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes: [grafana-data:/var/lib/grafana]
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports: ['9100:9100']
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
    restart: unless-stopped

volumes:
  prometheus-data:
  grafana-data:
EOF

# Configure firewall
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 22 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 80 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 443 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 3000 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 9090 >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

# Create management script
cat > /usr/local/bin/ies-manage << 'EOF'
#!/bin/bash
case \"\$1\" in
    start)
        systemctl start ies-analyzer nginx
        cd /opt/monitoring && docker compose start
        echo 'IES services started'
        ;;
    stop)
        systemctl stop ies-analyzer nginx
        cd /opt/monitoring && docker compose stop
        echo 'IES services stopped'
        ;;
    restart)
        systemctl restart ies-analyzer nginx
        cd /opt/monitoring && docker compose restart
        echo 'IES services restarted'
        ;;
    status)
        echo 'Application:' && systemctl is-active ies-analyzer
        echo 'Nginx:' && systemctl is-active nginx
        echo 'Monitoring:' && cd /opt/monitoring && docker compose ps --format table
        ;;
    logs)
        case \"\$2\" in
            app) journalctl -u ies-analyzer -f ;;
            nginx) journalctl -u nginx -f ;;
            monitoring) cd /opt/monitoring && docker compose logs -f ;;
            *) journalctl -u ies-analyzer --no-pager -n 20 ;;
        esac
        ;;
    update)
        cd /opt/IES && git pull && source ies_env/bin/activate && 
        pip install -r requirements.txt 2>/dev/null || true
        systemctl restart ies-analyzer
        echo 'Update complete'
        ;;
    *)
        echo 'Usage: \$0 {start|stop|restart|status|logs|update}'
        ;;
esac
EOF

chmod +x /usr/local/bin/ies-manage

# Start services
systemctl daemon-reload
systemctl enable ies-analyzer nginx ssh fail2ban >/dev/null 2>&1
systemctl start ies-analyzer nginx ssh fail2ban >/dev/null 2>&1

# Start monitoring
cd /opt/monitoring
docker compose up -d >/dev/null 2>&1

echo 'Setup completed successfully!'
"

msg_ok "Installation completed successfully!"

# Wait for services to start
msg_info "Starting services and running health checks..."
sleep 20

# Test application
if pct exec $CT_ID -- curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/health 2>/dev/null | grep -q "200"; then
    msg_ok "Application health check passed"
else
    msg_warn "Application may still be starting up"
fi

# Display completion message
echo
echo -e "${GREEN}=======================================${NC}"
echo -e "${GREEN}  IES Installation Complete!${NC}"
echo -e "${GREEN}=======================================${NC}"
echo
echo -e "${BLUE}Access Information:${NC}"
echo -e "Container ID:      ${GREEN}$CT_ID${NC}"
echo -e "IP Address:        ${GREEN}$IP${NC}"
echo -e "Root Password:     ${GREEN}$PASSWORD${NC}"
echo
echo -e "${BLUE}Application URLs:${NC}"
echo -e "Main App:          ${GREEN}https://$IP${NC}"
echo -e "Grafana:           ${GREEN}http://$IP:3000${NC} (admin/admin123)"
echo -e "Prometheus:        ${GREEN}http://$IP:9090${NC}"
echo -e "SSH Access:        ${GREEN}ssh root@$IP${NC}"
echo
echo -e "${BLUE}Management Commands:${NC}"
echo -e "Enter container:   ${YELLOW}pct enter $CT_ID${NC}"
echo -e "Start container:   ${YELLOW}pct start $CT_ID${NC}"
echo -e "Stop container:    ${YELLOW}pct stop $CT_ID${NC}"
echo
echo -e "${BLUE}Inside Container Commands:${NC}"
echo -e "Service control:   ${YELLOW}ies-manage {start|stop|restart|status}${NC}"
echo -e "View logs:         ${YELLOW}ies-manage logs [app|nginx|monitoring]${NC}"
echo -e "Update app:        ${YELLOW}ies-manage update${NC}"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Access the application at https://$IP"
echo "2. Configure DNS entry for $DOMAIN -> $IP"
echo "3. Replace self-signed SSL certificate if needed"
echo "4. Review monitoring dashboards in Grafana"
echo "5. Change default passwords"
echo
echo -e "${BLUE}Configuration:${NC}"
echo "All services are configured to start automatically"
echo "Firewall allows access from 192.168.0.0/24 only"
echo "SSH is enabled with password authentication"
echo
echo -e "${GREEN}Installation completed successfully!${NC}"

# Save configuration for reference
pct exec $CT_ID -- bash -c "
cat > /root/installation-info.txt << 'EOF'
IES Military Database Analyzer Installation Summary
==================================================

Installation Date: $(date)
Container ID: $CT_ID
Container Name: $CT_NAME
IP Address: $IP
Gateway: $GATEWAY
DNS Server: $DNS
Domain: $DOMAIN
Root Password: $PASSWORD

Access URLs:
- Application: https://$IP
- Grafana: http://$IP:3000 (admin/admin123)
- Prometheus: http://$IP:9090
- SSH: ssh root@$IP

Management:
- Service control: ies-manage {start|stop|restart|status|logs|update}
- Container access: pct enter $CT_ID (from Proxmox host)
- Container control: pct {start|stop|restart} $CT_ID

File Locations:
- Application: /opt/IES
- Configuration: /opt/IES/config
- Logs: /opt/IES/logs
- Nginx config: /etc/nginx/sites-available/ies-analyzer
- Monitoring: /opt/monitoring

Network Security:
- Firewall enabled (UFW)
- Access restricted to 192.168.0.0/24
- Fail2Ban active
- SSL/TLS enabled (self-signed certificate)

For support, check:
- Application logs: ies-manage logs app
- Service status: ies-manage status
- System logs: journalctl -u ies-analyzer
EOF
"

msg_ok "Installation information saved to /root/installation-info.txt inside container"
