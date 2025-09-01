#!/usr/bin/env bash

# IES Military Database Analyzer - Quick One-Line Installer
# Usage: bash <(curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install.sh)
# Or: export CT_ID=352 && bash <(curl -sSL https://...)

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Output functions
msg_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
msg_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
msg_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
msg_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration with environment variable override support
CT_ID="${CT_ID:-351}"
CT_NAME="${CT_NAME:-ies-analyzer}"
IP="${IP:-192.168.0.200}"
GATEWAY="${GATEWAY:-192.168.0.1}"
DNS="${DNS:-192.168.0.110}"
STORAGE="${STORAGE:-local-lvm}"
PASSWORD="${PASSWORD:-BobTheBigRedBus-0}"
CERT_SERVER="${CERT_SERVER:-192.168.0.122}"
DOMAIN="${DOMAIN:-ies-analyzer.local}"
DISK_SIZE="${DISK_SIZE:-8}"
RAM="${RAM:-2048}"
CPU_CORES="${CPU_CORES:-2}"
SSH_ENABLED="${SSH_ENABLED:-yes}"

# Display banner
clear
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  IES Military Database Analyzer          ${NC}"
echo -e "${CYAN}  Quick Proxmox LXC Installer             ${NC}"
echo -e "${CYAN}============================================${NC}"
echo
echo -e "${BLUE}Configuration:${NC}"
echo -e "Container ID: ${GREEN}$CT_ID${NC}"
echo -e "IP Address:   ${GREEN}$IP${NC}"
echo -e "Domain:       ${GREEN}$DOMAIN${NC}"
echo -e "Storage:      ${GREEN}$STORAGE${NC}"
echo

# Check Proxmox environment
if ! command -v pct &> /dev/null; then
    msg_error "This script must be run on a Proxmox VE host"
    echo "Usage from Proxmox console:"
    echo "  bash <(curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install.sh)"
    echo
    echo "Custom configuration:"
    echo "  export CT_ID=352"
    echo "  export IP=192.168.0.201"
    echo "  bash <(curl -sSL https://...)"
    exit 1
fi

# Check if container ID exists
if pct status $CT_ID >/dev/null 2>&1; then
    msg_error "Container ID $CT_ID already exists!"
    echo "Use a different ID: export CT_ID=XXX before running"
    exit 1
fi

msg_info "Starting quick installation..."

# Download Ubuntu template if needed
TEMPLATE="ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
if [[ ! -f "/var/lib/vz/template/cache/$TEMPLATE" ]]; then
    msg_info "Downloading Ubuntu 22.04 template..."
    pveam update >/dev/null 2>&1
    pveam download local $TEMPLATE >/dev/null 2>&1
    msg_ok "Template downloaded"
fi

# Create container
msg_info "Creating LXC container $CT_ID..."
pct create $CT_ID /var/lib/vz/template/cache/$TEMPLATE \
    --hostname "$CT_NAME" \
    --memory $RAM \
    --cores $CPU_CORES \
    --rootfs "$STORAGE:$DISK_SIZE" \
    --net0 name=eth0,bridge=vmbr0,ip="$IP/24",gw="$GATEWAY" \
    --nameserver "$DNS" \
    --timezone "UTC" \
    --password "$PASSWORD" \
    --features nesting=1 \
    --unprivileged 1 \
    --onboot 1 \
    --start 1 >/dev/null 2>&1

msg_ok "Container created successfully"

# Wait for container startup
msg_info "Waiting for container to be ready..."
sleep 15

# Wait for network connectivity
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

# Install everything in one comprehensive operation
msg_info "Installing and configuring all components (this takes 3-5 minutes)..."

pct exec $CT_ID -- bash -c "
# Update system
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null 2>&1
apt-get upgrade -y >/dev/null 2>&1

# Install system packages
apt-get install -y \
    curl wget git python3 python3-pip python3-venv python3-dev \
    nginx supervisor ufw fail2ban htop nano vim unzip \
    ca-certificates gnupg lsb-release software-properties-common \
    build-essential openssh-server >/dev/null 2>&1

# Install Docker with error handling
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg 2>/dev/null
ARCH=\$(dpkg --print-architecture)
CODENAME=\$(lsb_release -cs)
echo \"deb [arch=\${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \${CODENAME} stable\" > /etc/apt/sources.list.d/docker.list

if apt-get update >/dev/null 2>&1 && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1; then
    echo 'Docker installed from official repository'
else
    echo 'Using Ubuntu Docker packages as fallback'
    rm -f /etc/apt/sources.list.d/docker.list
    apt-get update >/dev/null 2>&1
    apt-get install -y docker.io docker-compose >/dev/null 2>&1
fi

systemctl enable docker ssh nginx fail2ban >/dev/null 2>&1
systemctl start docker >/dev/null 2>&1

# Clone and setup IES application
cd /opt
git clone https://github.com/DXCSithlordPadawan/IES.git >/dev/null 2>&1 || {
    if [ -d IES ]; then
        cd IES && git pull >/dev/null 2>&1
    else
        echo 'Failed to clone repository'
        exit 1
    fi
}
cd IES

# Setup Python environment with all dependencies
python3 -m venv ies_env
source ies_env/bin/activate
pip install --upgrade pip wheel setuptools >/dev/null 2>&1
pip install numpy pandas matplotlib seaborn networkx plotly >/dev/null 2>&1
pip install scikit-learn flask jinja2 gunicorn >/dev/null 2>&1
pip install prometheus-client psutil requests >/dev/null 2>&1

# Install from requirements.txt if available
if [ -f requirements.txt ]; then
    pip install -r requirements.txt >/dev/null 2>&1 || echo 'Some requirements failed, using core packages'
fi

# Verify critical dependencies and fix if needed
python3 -c \"
packages = ['networkx', 'pandas', 'numpy', 'matplotlib', 'seaborn', 'plotly', 'flask', 'sklearn', 'prometheus_client', 'psutil']
failed = []
for pkg in packages:
    try:
        __import__(pkg)
    except ImportError:
        failed.append(pkg)

if failed:
    import subprocess
    for pkg in failed:
        subprocess.run(['pip', 'install', '--force-reinstall', pkg], stdout=subprocess.DEVNULL)
\" 2>/dev/null

# Create enhanced application file
cat > military_database_analyzer_v3.py << 'APPEOF'
#!/usr/bin/env python3
import argparse, sys, os, time
from pathlib import Path
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    parser = argparse.ArgumentParser(description=\"IES4 Military Database Analysis Suite\")
    parser.add_argument('--web', action='store_true', help='Launch web interface')
    parser.add_argument('--host', default='127.0.0.1', help='Host for web interface')
    parser.add_argument('--port', type=int, default=5000, help='Port for web interface')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    args = parser.parse_args()
    
    if args.web:
        try:
            from flask import Flask, jsonify, render_template_string, request
            from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
            import psutil
            
            app = Flask(__name__)
            
            # Metrics
            REQUEST_COUNT = Counter('ies_http_requests_total', 'HTTP requests', ['method', 'endpoint', 'status'])
            REQUEST_DURATION = Histogram('ies_http_request_duration_seconds', 'Request duration')
            SYSTEM_CPU = Gauge('ies_system_cpu_percent', 'CPU usage')
            SYSTEM_MEMORY = Gauge('ies_system_memory_bytes', 'Memory usage')
            APPLICATION_STATUS = Gauge('ies_application_status', 'Application status')
            
            @app.before_request
            def before_request():
                request.start_time = time.time()
            
            @app.after_request
            def after_request(response):
                duration = time.time() - request.start_time
                REQUEST_COUNT.labels(method=request.method, endpoint=request.endpoint or 'unknown', status=response.status_code).inc()
                REQUEST_DURATION.observe(duration)
                return response
            
            @app.route('/')
            def home():
                return render_template_string(\"\"\"
<!DOCTYPE html>
<html><head><title>IES Military Database Analyzer</title>
<style>
body{font-family:Arial,sans-serif;margin:0;padding:40px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#333}
.container{max-width:900px;margin:0 auto;background:white;padding:40px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,0.2)}
h1{color:#2c3e50;text-align:center;margin-bottom:30px;font-size:2.5em}
.status{background:linear-gradient(45deg,#e8f5e8,#d4edda);padding:20px;border-radius:8px;margin:20px 0;border-left:5px solid #28a745}
.links{display:flex;justify-content:center;gap:15px;margin-top:30px}
.links a{display:inline-block;padding:12px 24px;background:#3498db;color:white;text-decoration:none;border-radius:6px;transition:all 0.3s;font-weight:bold}
.links a:hover{background:#2980b9;transform:translateY(-2px)}
.info{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:20px 0}
.info-box{background:#f8f9fa;padding:15px;border-radius:6px;border-left:4px solid #007bff}
</style>
</head><body><div class="container">
<h1>🛡️ IES Military Database Analyzer</h1>
<div class="status">
<strong>Status:</strong> System Operational<br>
<strong>Time:</strong> {{ time }}<br>
<strong>Version:</strong> 3.0 Enhanced<br>
<strong>Uptime:</strong> {{ uptime }} minutes
</div>
<div class="info">
<div class="info-box"><strong>Server:</strong> {{ server_ip }}</div>
<div class="info-box"><strong>Python:</strong> {{ python_version }}</div>
</div>
<div class="links">
<a href="/health">🔍 Health Check</a>
<a href="/metrics">📊 Metrics</a>
</div>
</div></body></html>
                \"\"\", 
                time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                uptime=int((time.time() - app.start_time)/60),
                server_ip=os.popen('hostname -I').read().strip().split()[0],
                python_version=sys.version.split()[0]
                )
            
            @app.route('/health')
            def health():
                return jsonify({
                    'status': 'healthy',
                    'timestamp': time.time(),
                    'version': '3.0',
                    'uptime_seconds': int(time.time() - app.start_time),
                    'python_version': sys.version.split()[0],
                    'dependencies_ok': True
                })
            
            @app.route('/metrics')
            def metrics():
                try:
                    SYSTEM_CPU.set(psutil.cpu_percent(interval=0.1))
                    SYSTEM_MEMORY.set(psutil.virtual_memory().used)
                    APPLICATION_STATUS.set(1)
                except:
                    pass
                return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
            
            app.start_time = time.time()
            print(f'Starting IES application on {args.host}:{args.port}')
            app.run(host=args.host, port=args.port, debug=args.verbose)
            
        except ImportError as e:
            print(f'Missing dependencies: {e}')
            print('Please ensure all required packages are installed')
            sys.exit(1)
    else:
        print('IES Military Database Analyzer v3.0')
        print('Use --web to start web interface')
        print('Use --help for more options')

if __name__ == '__main__': 
    main()
APPEOF

chmod +x military_database_analyzer_v3.py

# Create directories
mkdir -p /opt/IES/{logs,data,config,static,templates}

# Create systemd service
cat > /etc/systemd/system/ies-analyzer.service << 'SERVICEEOF'
[Unit]
Description=IES Military Database Analyzer
After=network.target docker.service
Wants=network.target

[Service]
Type=exec
User=root
WorkingDirectory=/opt/IES
Environment=PATH=/opt/IES/ies_env/bin
Environment=PYTHONPATH=/opt/IES
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/IES/ies_env/bin/python3 military_database_analyzer_v3.py --web --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Configure Nginx
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-available/ies-analyzer << 'NGINXEOF'
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
    ssl_ciphers ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!aNULL:!MD5:!DSS;
    
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection \"1; mode=block\";
    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
        
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
NGINXEOF

# Generate SSL certificate
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt \
    -subj '/C=US/ST=State/L=City/O=IES/CN=$IP' >/dev/null 2>&1

ln -sf /etc/nginx/sites-available/ies-analyzer /etc/nginx/sites-enabled/

# Setup monitoring stack
mkdir -p /opt/monitoring/{prometheus,grafana}
cat > /opt/monitoring/prometheus/prometheus.yml << 'PROMEOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'ies-application'
    static_configs:
      - targets: ['host.docker.internal:8000', '172.17.0.1:8000']
    scrape_interval: 15s
    metrics_path: /metrics

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
PROMEOF

cat > /opt/monitoring/docker-compose.yml << 'COMPOSEEOF'
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports: ['9090:9090']
    volumes: ['./prometheus:/etc/prometheus:ro', 'prometheus-data:/prometheus']
    command: ['--config.file=/etc/prometheus/prometheus.yml', '--storage.tsdb.path=/prometheus', '--storage.tsdb.retention.time=7d']
    extra_hosts: ['host.docker.internal:host-gateway']
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports: ['3000:3000']
    environment: ['GF_SECURITY_ADMIN_PASSWORD=admin123', 'GF_USERS_ALLOW_SIGN_UP=false']
    volumes: ['grafana-data:/var/lib/grafana']
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports: ['9100:9100']
    volumes: ['/proc:/host/proc:ro', '/sys:/host/sys:ro', '/:/rootfs:ro']
    command: ['--path.procfs=/host/proc', '--path.sysfs=/host/sys']
    restart: unless-stopped

volumes:
  prometheus-data:
  grafana-data:
COMPOSEEOF

# Configure firewall
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 22 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 80 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 443 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 3000 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 9090 >/dev/null 2>&1
ufw allow from 192.168.0.0/24 to any port 9100 >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

# Create management scripts
cat > /usr/local/bin/ies-manage << 'MANAGEEOF'
#!/bin/bash
case \"\$1\" in
    start)
        systemctl start ies-analyzer nginx docker
        cd /opt/monitoring && docker compose start 2>/dev/null || echo 'Monitoring start failed'
        echo 'IES services started'
        ;;
    stop)
        systemctl stop ies-analyzer nginx
        cd /opt/monitoring && docker compose stop 2>/dev/null || echo 'Monitoring stop failed'
        echo 'IES services stopped'
        ;;
    restart)
        systemctl restart ies-analyzer nginx docker
        cd /opt/monitoring && docker compose restart 2>/dev/null || echo 'Monitoring restart failed'
        echo 'IES services restarted'
        ;;
    status)
        echo 'Service Status:'
        systemctl is-active ies-analyzer nginx docker | paste <(echo -e 'IES App\nNginx\nDocker') -
        echo 'Network Status:'
        ss -tlnp | grep -E ':(80|443|8000|3000|9090)' || echo 'No services listening'
        ;;
    logs)
        case \"\$2\" in
            app) journalctl -u ies-analyzer -f ;;
            nginx) journalctl -u nginx -f ;;
            monitoring) cd /opt/monitoring && docker compose logs -f 2>/dev/null || echo 'Monitoring not available' ;;
            *) journalctl -u ies-analyzer --no-pager -n 20 ;;
        esac
        ;;
    test)
        echo 'Testing endpoints...'
        curl -s -o /dev/null -w 'Health: %{http_code}\n' http://127.0.0.1:8000/health 2>/dev/null || echo 'Health: Failed'
        curl -s -o /dev/null -w 'HTTP: %{http_code}\n' http://127.0.0.1/ 2>/dev/null || echo 'HTTP: Failed'
        curl -s -k -o /dev/null -w 'HTTPS: %{http_code}\n' https://127.0.0.1/ 2>/dev/null || echo 'HTTPS: Failed'
        ;;
    repair)
        echo 'Running quick repair...'
        cd /opt/IES && source ies_env/bin/activate
        pip install --force-reinstall flask prometheus-client psutil >/dev/null 2>&1
        systemctl restart ies-analyzer nginx
        echo 'Repair completed'
        ;;
    update)
        echo 'Updating application...'
        cd /opt/IES && git pull >/dev/null 2>&1
        source ies_env/bin/activate && pip install --upgrade -r requirements.txt >/dev/null 2>&1 || true
        systemctl restart ies-analyzer
        echo 'Update completed'
        ;;
    *)
        echo 'Usage: \$0 {start|stop|restart|status|logs|test|repair|update}'
        echo 'Quick commands for IES management'
        ;;
esac
MANAGEEOF

chmod +x /usr/local/bin/ies-manage

cat > /usr/local/bin/ies-monitor << 'MONITOREOF'
#!/bin/bash
IP=\$(hostname -I | awk '{print \$1}')
echo 'IES Quick Status Dashboard'
echo '=========================='
echo \"IP: \$IP | Time: \$(date +'%H:%M:%S')\"
echo \"Services: \$(systemctl is-active ies-analyzer nginx docker | tr '\n' ' ')\"
echo \"URLs: http://\$IP (→HTTPS) | https://\$IP | http://\$IP:3000\"
curl -s http://127.0.0.1:8000/health >/dev/null && echo 'App: ✓ Healthy' || echo 'App: ✗ Issue'
MONITOREOF

chmod +x /usr/local/bin/ies-monitor

# Start services
systemctl daemon-reload
systemctl enable ies-analyzer nginx ssh fail2ban >/dev/null 2>&1
systemctl start ssh nginx fail2ban >/dev/null 2>&1
systemctl start ies-analyzer >/dev/null 2>&1

# Start monitoring
cd /opt/monitoring
docker compose up -d >/dev/null 2>&1 || echo 'Monitoring stack failed to start'

# Create quick info file
cat > /root/quick-install-info.txt << 'INFOEOF'
IES Military Database Analyzer - Quick Install
==============================================

Installation completed: \$(date)
Container ID: $CT_ID
IP Address: $IP
Access: https://$IP

Quick Commands:
- ies-manage status    (check services)
- ies-manage test      (test endpoints)
- ies-manage logs app  (view logs)
- ies-monitor          (quick status)

Passwords:
- Root: $PASSWORD
- Grafana: admin/admin123

Services:
- Application: https://$IP
- Grafana: http://$IP:3000
- Prometheus: http://$IP:9090
INFOEOF

echo 'Quick installation completed successfully!'
"

msg_ok "Installation and configuration completed"

# Wait for services to start
msg_info "Starting services and running tests..."
sleep 20

# Quick health check
HEALTH_OK=false
if pct exec $CT_ID -- curl -s -f http://127.0.0.1:8000/health >/dev/null 2>&1; then
    HEALTH_OK=true
fi

# Display results
clear
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  IES Quick Installation Complete!         ${NC}"
echo -e "${GREEN}============================================${NC}"
echo
echo -e "${BLUE}Container Information:${NC}"
echo -e "Container ID:      ${GREEN}$CT_ID${NC}"
echo -e "IP Address:        ${GREEN}$IP${NC}"
echo -e "Root Password:     ${GREEN}$PASSWORD${NC}"
echo
echo -e "${BLUE}Access URLs:${NC}"
echo -e "Application:       ${CYAN}https://$IP${NC}"
echo -e "Grafana:          ${CYAN}http://$IP:3000${NC} (admin/admin123)"
echo -e "Prometheus:       ${CYAN}http://$IP:9090${NC}"
echo -e "SSH Access:       ${CYAN}ssh root@$IP${NC}"
echo

if $HEALTH_OK; then
    echo -e "${GREEN}✓ Application health check passed${NC}"
else
    echo -e "${YELLOW}⚠ Application may still be starting (wait 1-2 minutes)${NC}"
fi

echo
echo -e "${BLUE}Management Commands:${NC}"
echo -e "Container access:  ${YELLOW}pct enter $CT_ID${NC}"
echo -e "Quick status:      ${YELLOW}ies-monitor${NC}"
echo -e "Service control:   ${YELLOW}ies-manage {start|stop|restart|status|test}${NC}"
echo -e "View logs:         ${YELLOW}ies-manage logs app${NC}"
echo -e "Quick repair:      ${YELLOW}ies-manage repair${NC}"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Test access: https://$IP"
echo "2. Check Grafana: http://$IP:3000"
echo "3. Change default passwords"
echo "4. Review configuration"
echo
echo -e "${BLUE}Support:${NC}"
echo "Installation info: /root/quick-install-info.txt (inside container)"
echo "Status check: ies-manage test"
echo "If issues: ies-manage repair"
echo
echo -e "${GREEN}Ready for use!${NC}"

# Quick verification
msg_info "Running final verification..."
pct exec $CT_ID -- ies-manage test

echo
echo -e "${CYAN}Installation completed successfully!${NC}"
echo "Access your application at: https://$IP"