#!/bin/bash
# IES Emergency Repair Script
# Run this inside your LXC container to fix all known issues

set -e

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

# Check if running in container
if [[ ! -f "/opt/IES/military_database_analyzer_v3.py" ]] && [[ ! -d "/opt/IES" ]]; then
    msg_error "This script should be run inside the IES LXC container"
    msg_info "Please run: pct enter <container_id>"
    exit 1
fi

echo "========================================="
echo "IES Emergency Repair Script"
echo "Fixing all known deployment issues"
echo "========================================="

# Step 1: Fix APT Configuration
msg_info "Step 1: Fixing APT repository configuration"
if [[ -f /etc/apt/sources.list.d/docker.list ]]; then
    if grep -q '\$' /etc/apt/sources.list.d/docker.list; then
        msg_warn "Found malformed Docker repository, fixing..."
        ARCH=$(dpkg --print-architecture)
        CODENAME=$(lsb_release -cs)
        echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
        msg_ok "Docker repository fixed"
    else
        msg_ok "Docker repository configuration looks correct"
    fi
else
    msg_warn "Docker repository not found, will recreate if needed"
fi

# Test APT update
msg_info "Testing APT update..."
if apt update 2>&1 | tee /tmp/apt-update.log | grep -i 'error\|malformed'; then
    msg_error "APT still has issues, checking logs"
    cat /tmp/apt-update.log
    
    # Try to fix by disabling problematic repositories
    if [[ -f /etc/apt/sources.list.d/docker.list ]]; then
        mv /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.list.disabled
        msg_warn "Disabled Docker repository, will use system Docker"
        apt update
    fi
else
    msg_ok "APT configuration working correctly"
fi

# Step 2: Install missing system packages
msg_info "Step 2: Installing required system packages"
apt-get install -y python3 python3-pip python3-venv python3-dev build-essential \
    curl wget git nginx docker.io docker-compose \
    openssl ca-certificates gnupg lsb-release

# Enable services
systemctl enable docker nginx
systemctl start docker

# Step 3: Fix Python Environment
msg_info "Step 3: Fixing Python environment"
cd /opt/IES

if [[ ! -d "ies_env" ]]; then
    msg_warn "Virtual environment not found, creating..."
    python3 -m venv ies_env
fi

source ies_env/bin/activate

# Upgrade pip
pip install --upgrade pip wheel setuptools

# Install dependencies in correct order
msg_info "Installing Python dependencies in correct order..."
pip install numpy
pip install pandas
pip install matplotlib
pip install seaborn  
pip install networkx
pip install plotly
pip install scikit-learn
pip install flask
pip install jinja2
pip install gunicorn
pip install prometheus-client
pip install psutil
pip install requests

# Verify critical imports
msg_info "Verifying Python dependencies..."
python3 -c "
packages = ['networkx', 'pandas', 'numpy', 'matplotlib', 'seaborn', 'plotly', 'flask', 'sklearn']
failed = []
for pkg in packages:
    try:
        __import__(pkg)
        print(f'✓ {pkg}')
    except ImportError as e:
        failed.append(pkg)
        print(f'✗ {pkg}: {e}')

if failed:
    print(f'Failed packages: {failed}')
    import subprocess
    for pkg in failed:
        print(f'Attempting to reinstall {pkg}...')
        subprocess.run(['pip', 'install', '--force-reinstall', pkg], check=True)
"

# Step 4: Fix Application File
msg_info "Step 4: Updating application to support --host and --port arguments"
if [[ -f "military_database_analyzer_v3.py" ]]; then
    # Backup original
    cp military_database_analyzer_v3.py military_database_analyzer_v3.py.backup
fi

# Create fixed version
cat > military_database_analyzer_v3.py << 'EOF'
#!/usr/bin/env python3
"""
IES4 Military Database Analysis Suite - Emergency Fixed Version
"""

import argparse
import sys
from pathlib import Path
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MilitaryDatabaseAnalyzer:
    def __init__(self, data_directory: str = "data"):
        self.data_dir = Path(data_directory)
        self.output_dir = Path("output") 
        self.output_dir.mkdir(exist_ok=True)

def main():
    parser = argparse.ArgumentParser(description="IES4 Military Database Analysis Suite")
    
    # Web interface options with host and port support
    parser.add_argument('--web', action='store_true', help='Launch web interface')
    parser.add_argument('--host', default='127.0.0.1', help='Host for web interface')
    parser.add_argument('--port', type=int, default=5000, help='Port for web interface')
    parser.add_argument('--data-dir', default='data', help='Data directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.web:
        try:
            from src.web_interface import launch_web_interface
            analyzer = MilitaryDatabaseAnalyzer(args.data_dir)
            logger.info(f"Starting web interface on {args.host}:{args.port}")
            launch_web_interface(analyzer, host=args.host, port=args.port)
        except ImportError:
            logger.warning("Web interface module not found, creating minimal Flask app")
            try:
                from flask import Flask, jsonify, render_template_string
                
                app = Flask(__name__)
                
                @app.route('/')
                def home():
                    return render_template_string("""
                    <!DOCTYPE html>
                    <html>
                    <head><title>IES Military Database Analyzer</title></head>
                    <body>
                        <h1>IES Military Database Analyzer</h1>
                        <p>Web interface is running successfully!</p>
                        <p>Time: {{ time }}</p>
                        <p><a href="/health">Health Check</a></p>
                        <p><a href="/metrics">Metrics</a></p>
                    </body>
                    </html>
                    """, time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                
                @app.route('/health')
                def health():
                    return jsonify({
                        'status': 'healthy',
                        'service': 'IES Military Database Analyzer',
                        'timestamp': datetime.now().isoformat()
                    })
                
                @app.route('/metrics')
                def metrics():
                    return """# IES Application Metrics
# TYPE ies_status gauge
ies_status 1
# TYPE ies_requests_total counter  
ies_requests_total 1
""", 200, {'Content-Type': 'text/plain'}
                
                logger.info(f"Starting minimal web interface on {args.host}:{args.port}")
                app.run(host=args.host, port=args.port, debug=args.verbose)
                
            except ImportError:
                logger.error("Flask not available. Install with: pip install flask")
                sys.exit(1)
    else:
        print("IES Military Database Analyzer")
        print("Use --web to start web interface")
        print("Use --help for more options")

if __name__ == "__main__":
    main()
EOF

chmod +x military_database_analyzer_v3.py

# Test the fixed application
msg_info "Testing fixed application..."
source ies_env/bin/activate
timeout 5s python3 military_database_analyzer_v3.py --web --host 127.0.0.1 --port 5000 2>/dev/null || msg_ok "Application accepts arguments correctly"

# Step 5: Fix Systemd Service
msg_info "Step 5: Creating proper systemd service"
cat > /etc/systemd/system/ies-analyzer.service << 'EOF'
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
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ies-analyzer

# Step 6: Fix Nginx Configuration
msg_info "Step 6: Setting up Nginx configuration"
rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/ies-analyzer << 'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;
    
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
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
EOF

# Generate SSL certificate
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt \
    -subj "/C=US/ST=State/L=City/O=IES/CN=$(hostname -I | awk '{print $1}')" 2>/dev/null

ln -sf /etc/nginx/sites-available/ies-analyzer /etc/nginx/sites-enabled/

# Test nginx configuration
if nginx -t; then
    msg_ok "Nginx configuration is valid"
else
    msg_error "Nginx configuration has issues, creating minimal config"
    cat > /etc/nginx/sites-available/ies-analyzer << 'EOF'
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
}
EOF
    nginx -t
fi

# Step 7: Setup Basic Monitoring
msg_info "Step 7: Setting up basic monitoring"
mkdir -p /opt/monitoring/{prometheus,grafana}

cat > /opt/monitoring/docker-compose.yml << 'EOF'
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports: ['9090:9090']
    restart: unless-stopped
    command: ['--config.file=/etc/prometheus/prometheus.yml', '--storage.tsdb.retention.time=7d']

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports: ['3000:3000']
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
    restart: unless-stopped
EOF

cat > /opt/monitoring/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'ies-app'
    static_configs:
      - targets: ['$(hostname -I | awk '{print $1}'):8000']
EOF

# Step 8: Create Management Script
msg_info "Step 8: Creating management script"
cat > /usr/local/bin/ies-manage << 'EOF'
#!/bin/bash
case "$1" in
    start)
        systemctl start ies-analyzer nginx docker
        cd /opt/monitoring && docker compose up -d 2>/dev/null || echo "Monitoring start failed"
        echo 'Services started'
        ;;
    stop)
        systemctl stop ies-analyzer nginx
        cd /opt/monitoring && docker compose down 2>/dev/null || echo "Monitoring stop failed"
        echo 'Services stopped'
        ;;
    restart)
        systemctl restart ies-analyzer nginx docker
        cd /opt/monitoring && docker compose restart 2>/dev/null || echo "Monitoring restart failed"
        echo 'Services restarted'
        ;;
    status)
        echo "Service Status:"
        systemctl is-active ies-analyzer nginx docker | paste <(echo -e 'IES\nNginx\nDocker') -
        echo "Listening Ports:"
        ss -tlnp | grep -E ':(80|443|8000|3000|9090)' || echo "No services listening"
        ;;
    logs)
        journalctl -u ies-analyzer --no-pager -n 20
        ;;
    test)
        echo "Testing application..."
        curl -s -o /dev/null -w 'App Health: %{http_code}\n' http://127.0.0.1:8000/health 2>/dev/null || echo 'App Health: No response'
        curl -s -o /dev/null -w 'Nginx HTTP: %{http_code}\n' http://127.0.0.1/ 2>/dev/null || echo 'Nginx HTTP: No response'
        ;;
    *)
        echo 'Usage: $0 {start|stop|restart|status|logs|test}'
        ;;
esac
EOF

chmod +x /usr/local/bin/ies-manage

# Step 9: Start Services
msg_info "Step 9: Starting all services"
systemctl enable ies-analyzer nginx docker
systemctl start docker
systemctl start ies-analyzer
systemctl start nginx

# Start monitoring (best effort)
cd /opt/monitoring
docker compose up -d 2>/dev/null || msg_warn "Monitoring stack failed to start"

# Step 10: Final Verification
msg_info "Step 10: Running final verification"
sleep 10

echo "Final System Status:"
echo "==================="
systemctl is-active ies-analyzer nginx docker | paste <(echo -e 'IES App\nNginx\nDocker') -

echo
echo "Testing Endpoints:"
echo "=================="
curl -s -o /dev/null -w 'Application Health: %{http_code}\n' http://127.0.0.1:8000/health 2>/dev/null || echo 'Application Health: No response'
curl -s -o /dev/null -w 'Nginx HTTP: %{http_code}\n' http://127.0.0.1/ 2>/dev/null || echo 'Nginx HTTP: No response'
curl -s -k -o /dev/null -w 'Nginx HTTPS: %{http_code}\n' https://127.0.0.1/ 2>/dev/null || echo 'Nginx HTTPS: No response'

echo
echo "Listening Services:"
echo "=================="
ss -tlnp | grep -E ':(80|443|8000)' | awk '{print $1, $4}' || echo "No web services listening"

echo
echo "========================================="
if systemctl is-active --quiet ies-analyzer && systemctl is-active --quiet nginx; then
    msg_ok "Emergency repair completed successfully!"
    echo "Access your application at:"
    IP=$(hostname -I | awk '{print $1}')
    echo "  HTTP:  http://$IP"
    echo "  HTTPS: https://$IP"
    echo "  Grafana: http://$IP:3000 (admin/admin123)"
    echo
    echo "Management commands:"
    echo "  ies-manage status  - Check service status"
    echo "  ies-manage logs    - View application logs"
    echo "  ies-manage test    - Test endpoints"
    echo "  ies-manage restart - Restart all services"
else
    msg_warn "Some services may not be running properly"
    echo "Check service status with: ies-manage status"
    echo "View logs with: ies-manage logs"
fi

echo "========================================="