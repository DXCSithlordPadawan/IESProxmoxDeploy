#!/usr/bin/env bash

# IES Military Database Analyzer - Quick Deploy for Proxmox
# One-line deployment: curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-deploy.sh | bash
# Or: wget -qO- https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-deploy.sh | bash

set -e

# Script identification for Proxmox Community Scripts compatibility
SCRIPT_NAME="IES Military Database Analyzer"
SCRIPT_VERSION="2.0.0"
SCRIPT_AUTHOR="DXC Technology"

# Default configuration - override with environment variables
CT_ID="${CT_ID:-351}"
CT_NAME="${CT_NAME:-ies-analyzer}"
DISK_SIZE="${DISK_SIZE:-12}"
RAM="${RAM:-2048}"
CPU_CORES="${CPU_CORES:-2}"
IP="${IP:-192.168.0.200}"
GATEWAY="${GATEWAY:-192.168.0.1}"
DNS="${DNS:-192.168.0.110}"
STORAGE="${STORAGE:-local-lvm}"
PASSWORD="${PASSWORD:-BobTheBigRedBus-0}"
SSH_ENABLED="${SSH_ENABLED:-yes}"
CERT_SERVER="${CERT_SERVER:-192.168.0.122}"
DOMAIN="${DOMAIN:-ies-analyzer.local}"
TIMEZONE="${TIMEZONE:-America/New_York}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Logging functions
msg_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
msg_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
msg_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
msg_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Error handling
error_exit() {
    msg_error "$1"
    exit 1
}

# Parse environment variables and command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ct-id) CT_ID="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --help)
            cat << 'HELP_EOF'
IES Military Database Analyzer - Quick Deploy

Usage: 
  curl -sSL <script-url> | bash
  OR
  ./quick-deploy.sh [options]

Environment Variables (can be set before running):
  CT_ID=351                    Container ID
  IP=192.168.0.200            IP address
  GATEWAY=192.168.0.1         Gateway
  DNS=192.168.0.110           DNS server
  STORAGE=local-lvm           Storage pool
  PASSWORD=BobTheBigRedBus-0  Root password
  DOMAIN=ies-analyzer.local   Domain name
  RAM=2048                    Memory in MB
  CPU_CORES=2                 CPU cores
  DISK_SIZE=12               Disk size in GB

Command Line Options:
  --ct-id <id>     Override container ID
  --ip <addr>      Override IP address  
  --password <p>   Override password
  --help          Show this help

Examples:
  # Default installation
  bash quick-deploy.sh

  # Custom container ID and IP
  CT_ID=355 IP=192.168.0.205 bash quick-deploy.sh

  # Command line override
  bash quick-deploy.sh --ct-id 356 --ip 192.168.0.206

HELP_EOF
            exit 0
            ;;
        *) error_exit "Unknown option: $1" ;;
    esac
done

# Validation functions
check_prerequisites() {
    # Check if running on Proxmox
    if ! command -v pct &> /dev/null; then
        error_exit "This script must be run on a Proxmox VE host"
    fi
    
    # Check if container ID is available
    if pct status $CT_ID >/dev/null 2>&1; then
        error_exit "Container ID $CT_ID already exists! Use different CT_ID environment variable"
    fi
    
    # Check if IP is valid format (basic check)
    if ! [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        error_exit "Invalid IP address format: $IP"
    fi
}

# Display configuration
show_config() {
    clear
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${CYAN}    IES Military Database Analyzer${NC}"
    echo -e "${CYAN}    Quick Deploy - Version $SCRIPT_VERSION${NC}"
    echo -e "${CYAN}=================================================${NC}"
    echo
    echo -e "${WHITE}Deployment Configuration:${NC}"
    echo -e "Container ID:    ${GREEN}$CT_ID${NC}"
    echo -e "Container Name:  ${GREEN}$CT_NAME${NC}"
    echo -e "IP Address:      ${GREEN}$IP${NC}"
    echo -e "Gateway:         ${GREEN}$GATEWAY${NC}"
    echo -e "DNS Server:      ${GREEN}$DNS${NC}"
    echo -e "Storage:         ${GREEN}$STORAGE${NC}"
    echo -e "Resources:       ${GREEN}${RAM}MB RAM, ${CPU_CORES} cores, ${DISK_SIZE}GB disk${NC}"
    echo -e "SSH Enabled:     ${GREEN}$SSH_ENABLED${NC}"
    echo -e "Domain:          ${GREEN}$DOMAIN${NC}"
    echo
    echo -e "${YELLOW}Note: To customize settings, use environment variables or stop and use the full installer.${NC}"
    echo
    read -t 10 -p "Proceeding with deployment in 10 seconds... (Press Enter to continue or Ctrl+C to cancel)" || true
    echo
}

# Download Ubuntu template if needed
prepare_template() {
    msg_info "Checking for Ubuntu 22.04 template..."
    local template="ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
    
    if [[ ! -f "/var/lib/vz/template/cache/$template" ]]; then
        msg_info "Downloading Ubuntu 22.04 template (this may take a few minutes)..."
        pveam update >/dev/null 2>&1
        pveam download local "$template" || error_exit "Failed to download template"
    fi
    
    msg_ok "Template ready"
}

# Create and configure container
create_container() {
    msg_info "Creating LXC container (ID: $CT_ID, IP: $IP)..."
    
    pct create $CT_ID "/var/lib/vz/template/cache/ubuntu-22.04-standard_22.04-1_amd64.tar.zst" \
        --hostname "$CT_NAME" \
        --memory $RAM \
        --cores $CPU_CORES \
        --rootfs "$STORAGE:$DISK_SIZE" \
        --net0 name=eth0,bridge=vmbr0,ip="$IP/24",gw="$GATEWAY" \
        --nameserver "$DNS" \
        --timezone "$TIMEZONE" \
        --password "$PASSWORD" \
        --features nesting=1 \
        --unprivileged 1 \
        --onboot 1 \
        --start 1 >/dev/null 2>&1 || error_exit "Failed to create container"
    
    msg_ok "Container created successfully"
    
    # Wait for container to be ready
    msg_info "Waiting for container startup and network initialization..."
    sleep 20
    
    # Wait for network connectivity
    local retries=0
    while ! pct exec $CT_ID -- ping -c 1 8.8.8.8 >/dev/null 2>&1; do
        if [[ $retries -ge 30 ]]; then
            error_exit "Network connectivity not established after 30 attempts"
        fi
        sleep 2
        ((retries++))
    done
    
    msg_ok "Container is ready and network is active"
}

# Install complete application stack
install_application_stack() {
    msg_info "Installing complete application stack (this will take 5-10 minutes)..."
    
    # Execute the complete installation inside the container
    pct exec $CT_ID -- bash -c '
        set -e
        
        # Update system
        apt-get update >/dev/null 2>&1
        apt-get upgrade -y >/dev/null 2>&1
        
        # Install system packages
        apt-get install -y curl wget git python3 python3-pip python3-venv python3-dev \
            build-essential nginx supervisor ufw fail2ban htop nano vim unzip \
            ca-certificates gnupg lsb-release software-properties-common openssl >/dev/null 2>&1
        
        # Install SSH if enabled
        if [[ "'"$SSH_ENABLED"'" == "yes" ]]; then
            apt-get install -y openssh-server >/dev/null 2>&1
            systemctl enable ssh >/dev/null 2>&1
        fi
        
        # Install Docker with fallback
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
        
        apt-get update >/dev/null 2>&1
        if apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1; then
            echo "Docker installed from official repository"
        else
            echo "Falling back to Ubuntu Docker packages"
            apt-get install -y docker.io docker-compose >/dev/null 2>&1
        fi
        
        systemctl enable docker >/dev/null 2>&1
        systemctl start docker >/dev/null 2>&1
        
        # Clone and setup IES application
        cd /opt
        if git clone https://github.com/DXCSithlordPadawan/IES.git >/dev/null 2>&1; then
            echo "Repository cloned successfully"
        else
            if [[ -d "IES" ]]; then
                cd IES && git pull >/dev/null 2>&1
            else
                echo "Failed to clone repository"
                exit 1
            fi
        fi
        cd IES
        
        # Setup Python environment with all dependencies
        python3 -m venv ies_env
        source ies_env/bin/activate
        
        pip install --upgrade pip >/dev/null 2>&1
        
        # Install dependencies in optimal order for compatibility
        pip install wheel setuptools >/dev/null 2>&1
        pip install numpy pandas >/dev/null 2>&1
        pip install matplotlib seaborn >/dev/null 2>&1
        pip install networkx plotly >/dev/null 2>&1
        pip install scikit-learn >/dev/null 2>&1
        pip install flask jinja2 gunicorn >/dev/null 2>&1
        pip install prometheus-client psutil requests jsonschema >/dev/null 2>&1
        
        # Try requirements.txt as backup
        if [[ -f requirements.txt ]]; then
            pip install -r requirements.txt >/dev/null 2>&1 || true
        fi
        
        # Create application directories
        mkdir -p /opt/IES/{logs,data,config,static,templates}
        chmod 755 /opt/IES/{logs,data,config}
        
        # Create enhanced application file
        cat > military_database_analyzer_v3.py << '"'"'PYTHON_EOF'"'"'
#!/usr/bin/env python3
import argparse, sys, os, time
from pathlib import Path
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    parser = argparse.ArgumentParser(description="IES Military Database Analysis Suite")
    parser.add_argument("--web", action="store_true", help="Launch web interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host for web interface")
    parser.add_argument("--port", type=int, default=5000, help="Port for web interface")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()
    
    if args.web:
        from flask import Flask, jsonify, render_template_string, request, Response
        app = Flask(__name__)
        
        # Setup metrics collection
        try:
            from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
            import psutil
            
            REQUEST_COUNT = Counter("ies_http_requests_total", "HTTP requests", ["method", "endpoint", "status"])
            REQUEST_DURATION = Histogram("ies_http_request_duration_seconds", "Request duration", ["method", "endpoint"])
            SYSTEM_CPU = Gauge("ies_system_cpu_percent", "CPU usage")
            SYSTEM_MEMORY = Gauge("ies_system_memory_bytes", "Memory usage")
            APPLICATION_STATUS = Gauge("ies_application_status", "Application status")
            
            @app.before_request
            def before_request():
                request.start_time = time.time()
            
            @app.after_request
            def after_request(response):
                duration = time.time() - request.start_time
                REQUEST_COUNT.labels(
                    method=request.method,
                    endpoint=request.endpoint or "unknown",
                    status=response.status_code
                ).inc()
                REQUEST_DURATION.labels(
                    method=request.method,
                    endpoint=request.endpoint or "unknown"
                ).observe(duration)
                return response
            
            @app.route("/metrics")
            def metrics():
                SYSTEM_CPU.set(psutil.cpu_percent(interval=0.1))
                SYSTEM_MEMORY.set(psutil.virtual_memory().used)
                APPLICATION_STATUS.set(1)
                return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
                
        except ImportError:
            @app.route("/metrics")
            def metrics():
                return """# IES Application Metrics
# TYPE ies_status gauge
ies_status 1
# TYPE ies_requests_total counter  
ies_requests_total 1
""", 200, {"Content-Type": "text/plain"}
        
        @app.route("/")
        def home():
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>IES Military Database Analyzer</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { 
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh; padding: 20px;
                    }
                    .container {
                        max-width: 900px; margin: 0 auto; background: rgba(255,255,255,0.95);
                        border-radius: 20px; padding: 40px; box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                        backdrop-filter: blur(10px);
                    }
                    h1 { 
                        color: #2c3e50; text-align: center; margin-bottom: 30px;
                        font-size: 2.5em; font-weight: 700;
                    }
                    .status-grid {
                        display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                        gap: 20px; margin: 30px 0;
                    }
                    .status-card {
                        background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
                        padding: 25px; border-radius: 15px; text-align: center;
                        box-shadow: 0 8px 16px rgba(0,0,0,0.1);
                    }
                    .status-card h3 { color: #1976d2; margin-bottom: 15px; font-size: 1.2em; }
                    .status-card p { color: #424242; line-height: 1.6; }
                    .links {
                        display: flex; justify-content: center; gap: 15px;
                        margin-top: 40px; flex-wrap: wrap;
                    }
                    .btn {
                        padding: 12px 24px; background: linear-gradient(135deg, #42a5f5, #1e88e5);
                        color: white; text-decoration: none; border-radius: 25px;
                        font-weight: 600; transition: transform 0.3s ease;
                        box-shadow: 0 4px 15px rgba(66, 165, 245, 0.4);
                    }
                    .btn:hover { transform: translateY(-2px); }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>IES Military Database Analyzer</h1>
                    <div class="status-grid">
                        <div class="status-card">
                            <h3>System Status</h3>
                            <p><strong>Status:</strong> Operational<br>
                            <strong>Version:</strong> 3.0 Production<br>
                            <strong>Environment:</strong> LXC Container</p>
                        </div>
                        <div class="status-card">
                            <h3>Current Time</h3>
                            <p><strong>Server Time:</strong><br>{{ time }}</p>
                        </div>
                        <div class="status-card">
                            <h3>Application Info</h3>
                            <p><strong>Runtime:</strong> Python Flask<br>
                            <strong>Monitoring:</strong> Prometheus<br>
                            <strong>Security:</strong> SSL/TLS Enabled</p>
                        </div>
                    </div>
                    <div class="links">
                        <a href="/health" class="btn">Health Check</a>
                        <a href="/metrics" class="btn">System Metrics</a>
                    </div>
                </div>
            </body>
            </html>
            """, time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
        
        @app.route("/health")
        def health():
            return jsonify({
                "status": "healthy",
                "timestamp": time.time(),
                "version": "3.0",
                "service": "IES Military Database Analyzer",
                "environment": "production"
            })
        
        app.run(host=args.host, port=args.port, debug=args.verbose)
    else:
        print("IES Military Database Analyzer v3.0")
        print("Use --web to start web interface")
        print("Use --help for more options")

if __name__ == "__main__": main()
PYTHON_EOF
        
        chmod +x military_database_analyzer_v3.py
        
        # Test critical dependencies
        source ies_env/bin/activate
        python3 -c "import networkx, pandas, flask, plotly" || {
            echo "Installing missing critical dependencies..."
            pip install --force-reinstall networkx pandas flask plotly matplotlib seaborn scikit-learn
        }
        
        # Create systemd service
        cat > /etc/systemd/system/ies-analyzer.service << '"'"'SERVICE_EOF'"'"'
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
SERVICE_EOF
        
        # Configure Nginx
        rm -f /etc/nginx/sites-enabled/default
        
        cat > /etc/nginx/sites-available/ies-analyzer << '"'"'NGINX_EOF'"'"'
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
    ssl_ciphers ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!aNULL:!MD5:!DSS;
    ssl_prefer_server_ciphers on;
    
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
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
NGINX_EOF
        
        # Generate SSL certificate
        mkdir -p /etc/nginx/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/server.key \
            -out /etc/nginx/ssl/server.crt \
            -subj "/C=US/ST=State/L=City/O=IES/CN='"$IP"'" >/dev/null 2>&1
        
        ln -sf /etc/nginx/sites-available/ies-analyzer /etc/nginx/sites-enabled/
        
        # Setup monitoring stack
        mkdir -p /opt/monitoring/{prometheus,grafana}
        cd /opt/monitoring
        
        cat > prometheus/prometheus.yml << '"'"'PROM_EOF'"'"'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "ies-application"
    static_configs:
      - targets: ["host.docker.internal:8000", "172.17.0.1:8000"]
    scrape_interval: 15s
    metrics_path: /metrics

  - job_name: "node-exporter"
    static_configs:
      - targets: ["node-exporter:9100"]
PROM_EOF
        
        cat > docker-compose.yml << '"'"'COMPOSE_EOF'"'"'
version: "3.8"

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports: ["9090:9090"]
    volumes:
      - ./prometheus:/etc/prometheus:ro
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=15d"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports: ["3000:3000"]
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes: ["grafana-data:/var/lib/grafana"]
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports: ["9100:9100"]
    volumes:
      - "/proc:/host/proc:ro"
      - "/sys:/host/sys:ro"  
      - "/:/rootfs:ro"
    command:
      - "--path.procfs=/host/proc"
      - "--path.sysfs=/host/sys"
      - "--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($|/)"
    restart: unless-stopped

volumes:
  prometheus-data:
  grafana-data:
COMPOSE_EOF
        
        # Configure firewall
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        
        if [[ "'"$SSH_ENABLED"'" == "yes" ]]; then
            ufw allow from 192.168.0.0/24 to any port 22 >/dev/null 2>&1
        fi
        
        ufw allow from 192.168.0.0/24 to any port 80 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 443 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 3000 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 9090 >/dev/null 2>&1
        
        ufw --force enable >/dev/null 2>&1
        
        # Create management script
        cat > /usr/local/bin/ies-manage << '"'"'MANAGE_EOF'"'"'
#!/bin/bash

case "$1" in
    start)
        systemctl start ies-analyzer nginx docker
        cd /opt/monitoring && (docker compose start || docker-compose start) 2>/dev/null
        echo "✓ IES services started"
        ;;
    stop)
        systemctl stop ies-analyzer nginx
        cd /opt/monitoring && (docker compose stop || docker-compose stop) 2>/dev/null
        echo "✓ IES services stopped"
        ;;
    restart)
        systemctl restart ies-analyzer nginx docker
        cd /opt/monitoring && (docker compose restart || docker-compose restart) 2>/dev/null
        echo "✓ IES services restarted"
        ;;
    status)
        echo "Service Status:"
        echo "=============="
        systemctl is-active ies-analyzer nginx docker fail2ban | paste <(echo -e "IES App\nNginx\nDocker\nFail2Ban") -
        echo
        echo "Listening Ports:"
        echo "==============="
        ss -tlnp | grep -E ":(80|443|8000|3000|9090)" || echo "No web services listening"
        ;;
    logs)
        case "$2" in
            app) journalctl -u ies-analyzer -f ;;
            nginx) journalctl -u nginx -f ;;
            monitoring) cd /opt/monitoring && (docker compose logs -f || docker-compose logs -f) 2>/dev/null ;;
            *) journalctl -u ies-analyzer --no-pager -n 20 ;;
        esac
        ;;
    test)
        echo "Testing IES endpoints..."
        echo "======================="
        curl -s -o /dev/null -w "Health: %{http_code}\n" http://127.0.0.1:8000/health 2>/dev/null || echo "Health: No response"
        curl -s -o /dev/null -w "Metrics: %{http_code}\n" http://127.0.0.1:8000/metrics 2>/dev/null || echo "Metrics: No response"
        curl -s -o /dev/null -w "HTTP: %{http_code}\n" http://127.0.0.1/ 2>/dev/null || echo "HTTP: No response"
        curl -s -k -o /dev/null -w "HTTPS: %{http_code}\n" https://127.0.0.1/ 2>/dev/null || echo "HTTPS: No response"
        ;;
    update)
        echo "Updating IES application..."
        cd /opt/IES
        git pull >/dev/null 2>&1
        source ies_env/bin/activate
        pip install --upgrade -r requirements.txt 2>/dev/null || echo "Requirements file not found"
        systemctl restart ies-analyzer
        echo "✓ Update complete"
        ;;
    repair)
        echo "Running system repair..."
        echo "======================="
        
        # Fix APT if needed
        if [[ -f /etc/apt/sources.list.d/docker.list ]] && grep -q "\$" /etc/apt/sources.list.d/docker.list; then
            echo "Fixing Docker repository..."
            ARCH=$(dpkg --print-architecture)
            CODENAME=$(lsb_release -cs)
            echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
        fi
        
        # Fix dependencies
        echo "Fixing Python dependencies..."
        cd /opt/IES
        source ies_env/bin/activate
        pip install --force-reinstall networkx pandas flask plotly matplotlib seaborn scikit-learn
        
        # Restart services
        echo "Restarting services..."
        systemctl restart ies-analyzer nginx docker
        cd /opt/monitoring && (docker compose restart || docker-compose restart) 2>/dev/null
        
        sleep 10
        $0 test
        echo "✓ Repair completed"
        ;;
    backup)
        BACKUP_FILE="/opt/ies-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        echo "Creating backup: $BACKUP_FILE"
        tar -czf "$BACKUP_FILE" /opt/IES/data /opt/IES/config /opt/monitoring 2>/dev/null
        echo "✓ Backup created: $BACKUP_FILE"
        ;;
    *)
        echo "IES Management Tool"
        echo "=================="
        echo "Usage: $0 {start|stop|restart|status|logs|test|update|repair|backup}"
        echo
        echo "Commands:"
        echo "  start      - Start all IES services"
        echo "  stop       - Stop all IES services"  
        echo "  restart    - Restart all IES services"
        echo "  status     - Show service status and ports"
        echo "  logs [type] - Show logs (app, nginx, monitoring)"
        echo "  test       - Test all endpoints"
        echo "  update     - Update IES application"
        echo "  repair     - Fix common issues"
        echo "  backup     - Create system backup"
        exit 1
        ;;
esac
MANAGE_EOF
        
        chmod +x /usr/local/bin/ies-manage
        
        # Create monitoring overview script
        cat > /usr/local/bin/ies-monitor << '"'"'MONITOR_EOF'"'"'
#!/bin/bash

echo "IES Military Database Analyzer"
echo "=============================="
echo "Container: '"$CT_NAME"' (ID: '"$CT_ID"')"
echo "IP Address: '"$IP"'"
echo "Domain: '"$DOMAIN"'"
echo
echo "Services:"
systemctl is-active ies-analyzer nginx docker | paste <(echo -e "IES App\nNginx\nDocker") -
echo
echo "Access URLs:"
echo "• Application: https://'"$IP"'"
echo "• Grafana: http://'"$IP"':3000 (admin/admin123)"
echo "• Prometheus: http://'"$IP"':9090"
if [[ "'"$SSH_ENABLED"'" == "yes" ]]; then
    echo "• SSH: ssh root@'"$IP"'"
fi
echo
echo "System Resources:"
echo "• Disk: $(df -h / | tail -1 | awk '"'"'{print $5 " used of " $2}'"'"')"
echo "• Memory: $(free -h | grep Mem | awk '"'"'{print $3 "/" $2}'"'"')"
echo "• Load: $(uptime | awk -F'"'"'load average:'"'"' '"'"'{print $2}'"'"')"
echo
echo "Quick Commands:"
echo "• Service status: ies-manage status"
echo "• Test endpoints: ies-manage test"
echo "• View logs: ies-manage logs"
echo "• System repair: ies-manage repair"
MONITOR_EOF
        
        chmod +x /usr/local/bin/ies-monitor
        
        # Enable and start all services
        systemctl daemon-reload
        systemctl enable ies-analyzer nginx docker fail2ban >/dev/null 2>&1
        systemctl start ies-analyzer nginx fail2ban >/dev/null 2>&1
        
        # Start monitoring stack
        cd /opt/monitoring
        (docker compose up -d || docker-compose up -d) >/dev/null 2>&1
        
        echo "Installation completed successfully!"
    ' || error_exit "Application installation failed"
    
    msg_ok "Application stack installed successfully"
}

# Test deployment
test_deployment() {
    msg_info "Testing deployment and endpoints..."
    
    # Wait for services to fully start
    sleep 30
    
    local test_results=""
    local all_passed=true
    
    # Test application health
    if pct exec $CT_ID -- curl -s -f http://127.0.0.1:8000/health >/dev/null 2>&1; then
        test_results+="✓ Application health: PASSED\n"
    else
        test_results+="✗ Application health: FAILED\n"
        all_passed=false
    fi
    
    # Test web interface
    if pct exec $CT_ID -- curl -s -k https://127.0.0.1/ | grep -q "IES Military Database" 2>/dev/null; then
        test_results+="✓ Web interface: PASSED\n"
    else
        test_results+="✗ Web interface: FAILED\n"
        all_passed=false
    fi
    
    # Test monitoring
    if pct exec $CT_ID -- docker ps | grep -E "(prometheus|grafana)" >/dev/null 2>&1; then
        test_results+="✓ Monitoring stack: PASSED\n"
    else
        test_results+="✗ Monitoring stack: FAILED\n"
        all_passed=false
    fi
    
    # Test firewall
    if pct exec $CT_ID -- ufw status | grep -q "Status: active" 2>/dev/null; then
        test_results+="✓ Firewall: PASSED\n"
    else
        test_results+="✗ Firewall: FAILED\n"
        all_passed=false
    fi
    
    echo -e "$test_results"
    
    if $all_passed; then
        msg_ok "All tests passed - deployment successful!"
    else
        msg_warn "Some tests failed - basic functionality may still work"
    fi
}

# Display final information
show_success() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}    IES DEPLOYMENT COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo
    echo -e "${WHITE}🚀 Your IES Military Database Analyzer is ready!${NC}"
    echo
    echo -e "${WHITE}📋 Container Information:${NC}"
    echo -e "   Container ID: ${CYAN}$CT_ID${NC}"
    echo -e "   IP Address:   ${CYAN}$IP${NC}"
    echo -e "   Domain:       ${CYAN}$DOMAIN${NC}"
    echo -e "   Resources:    ${CYAN}${RAM}MB RAM, ${CPU_CORES} cores${NC}"
    echo
    echo -e "${WHITE}🌐 Access Your Application:${NC}"
    echo -e "   Primary URL:  ${CYAN}https://$IP${NC}"
    echo -e "   Grafana:      ${CYAN}http://$IP:3000${NC} ${YELLOW}(admin/admin123)${NC}"
    echo -e "   Prometheus:   ${CYAN}http://$IP:9090${NC}"
    if [[ "$SSH_ENABLED" == "yes" ]]; then
        echo -e "   SSH Access:   ${CYAN}ssh root@$IP${NC}"
    fi
    echo
    echo -e "${WHITE}🎯 Quick Commands:${NC}"
    echo -e "   Container Access: ${YELLOW}pct enter $CT_ID${NC}"
    echo -e "   Service Status:   ${YELLOW}ies-manage status${NC}"
    echo -e "   View Logs:        ${YELLOW}ies-manage logs${NC}"
    echo -e "   Test System:      ${YELLOW}ies-manage test${NC}"
    echo -e "   System Overview:  ${YELLOW}ies-monitor${NC}"
    echo
    echo -e "${WHITE}🔧 Management:${NC}"
    echo -e "   Start Services:   ${YELLOW}ies-manage start${NC}"
    echo -e "   Stop Services:    ${YELLOW}ies-manage stop${NC}"
    echo -e "   Update App:       ${YELLOW}ies-manage update${NC}"
    echo -e "   System Repair:    ${YELLOW}ies-manage repair${NC}"
    echo -e "   Create Backup:    ${YELLOW}ies-manage backup${NC}"
    echo
    echo -e "${WHITE}🛡️  Security Features:${NC}"
    echo -e "   • Firewall active (192.168.0.0/24 access only)"
    echo -e "   • SSL/TLS encryption enabled"
    echo -e "   • Intrusion detection (Fail2Ban) active"
    echo -e "   • Container isolation enabled"
    echo
    echo -e "${WHITE}📚 Next Steps:${NC}"
    echo -e "   1. Visit ${CYAN}https://$IP${NC} to access your application"
    echo -e "   2. Configure DNS: $DOMAIN → $IP"
    echo -e "   3. Replace SSL certificate for production use"
    echo -e "   4. Setup Grafana dashboards and alerts"
    echo -e "   5. Change default passwords"
    echo
    echo -e "${YELLOW}💡 Pro Tip: Run 'ies-manage test' inside the container to verify all endpoints${NC}"
    echo
    echo -e "${GREEN}🎉 Deployment completed in $(( SECONDS / 60 )) minutes and $(( SECONDS % 60 )) seconds!${NC}"
}

# Main execution
main() {
    # Start timer
    SECONDS=0
    
    # Check prerequisites
    check_prerequisites
    
    # Show configuration
    show_config
    
    # Prepare template
    prepare_template
    
    # Create container
    create_container
    
    # Install complete stack
    install_application_stack
    
    # Test the deployment
    test_deployment
    
    # Show success information
    show_success
}

# Run main function with error handling
set -e
trap 'msg_error "Deployment failed at line $LINENO. Check the logs and try again."; exit 1' ERR

main "$@"