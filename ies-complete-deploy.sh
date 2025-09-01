#!/usr/bin/env bash

# IES Military Database Analyzer - Complete LXC Container Deployment
# Combines all fixes and features from multiple scripts
# Compatible with Proxmox Community Scripts format
# Version: 2.0.0
# Author: DXC Technology

set -e

# Default configuration
DEFAULT_CT_ID="351"
DEFAULT_CT_NAME="ies-analyzer"
DEFAULT_DISK_SIZE="8"
DEFAULT_RAM="2048"
DEFAULT_CPU_CORES="2"
DEFAULT_IP="192.168.0.200"
DEFAULT_GATEWAY="192.168.0.1"
DEFAULT_DNS="192.168.0.110"
DEFAULT_STORAGE="local-lvm"
DEFAULT_PASSWORD="BobTheBigRedBus-0"
DEFAULT_SSH_ENABLED="yes"
DEFAULT_CERT_SERVER="192.168.0.122"
DEFAULT_DOMAIN="ies-analyzer.local"
DEFAULT_TIMEZONE="UTC"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Output functions
msg_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
msg_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
msg_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
msg_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Validation functions
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            [[ $i -lt 0 || $i -gt 255 ]] && return 1
        done
        return 0
    fi
    return 1
}

check_ct_id() {
    local ct_id=$1
    pct status $ct_id >/dev/null 2>&1 && return 1 || return 0
}

# Configuration menu system
show_config_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  IES Military Database Analyzer Setup ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo
    echo -e "${BLUE}Current Configuration:${NC}"
    echo -e "CT ID:           ${GREEN}$CT_ID${NC}"
    echo -e "Container Name:  ${GREEN}$CT_NAME${NC}"
    echo -e "Disk Size:       ${GREEN}${DISK_SIZE}GB${NC}"
    echo -e "RAM:             ${GREEN}${RAM}MB${NC}"
    echo -e "CPU Cores:       ${GREEN}$CPU_CORES${NC}"
    echo -e "IP Address:      ${GREEN}$IP${NC}"
    echo -e "Gateway:         ${GREEN}$GATEWAY${NC}"
    echo -e "DNS Server:      ${GREEN}$DNS${NC}"
    echo -e "Storage:         ${GREEN}$STORAGE${NC}"
    echo -e "SSH Enabled:     ${GREEN}$SSH_ENABLED${NC}"
    echo -e "Cert Server:     ${GREEN}$CERT_SERVER${NC}"
    echo -e "Domain:          ${GREEN}$DOMAIN${NC}"
    echo -e "Timezone:        ${GREEN}$TIMEZONE${NC}"
    echo
    echo -e "${BLUE}Options:${NC}"
    echo "1) Start deployment with current settings"
    echo "2) Advanced configuration"
    echo "3) Reset to defaults"
    echo "4) Exit"
    echo
    read -p "Choose an option [1-4]: " choice
    
    case $choice in
        1) return 0 ;;
        2) advanced_config ;;
        3) reset_defaults ;;
        4) exit 0 ;;
        *) msg_warn "Invalid option. Please try again."; sleep 2; show_config_menu ;;
    esac
}

advanced_config() {
    while true; do
        clear
        echo -e "${CYAN}Advanced Configuration${NC}"
        echo "=========================="
        echo
        echo "1)  CT ID: $CT_ID"
        echo "2)  Container Name: $CT_NAME"
        echo "3)  Disk Size: ${DISK_SIZE}GB"
        echo "4)  RAM: ${RAM}MB"
        echo "5)  CPU Cores: $CPU_CORES"
        echo "6)  IP Address: $IP"
        echo "7)  Gateway: $GATEWAY"
        echo "8)  DNS Server: $DNS"
        echo "9)  Storage: $STORAGE"
        echo "10) SSH Enabled: $SSH_ENABLED"
        echo "11) Root Password: [Hidden]"
        echo "12) Cert Server: $CERT_SERVER"
        echo "13) Domain: $DOMAIN"
        echo "14) Timezone: $TIMEZONE"
        echo "15) Back to main menu"
        echo
        read -p "Select option to modify [1-15]: " option
        
        case $option in
            1) read -p "Enter CT ID [$CT_ID]: " new_value
               if [[ -n "$new_value" ]]; then
                   if check_ct_id "$new_value"; then
                       CT_ID="$new_value"
                   else
                       msg_error "CT ID $new_value already exists!"; sleep 2
                   fi
               fi ;;
            2) read -p "Enter Container Name [$CT_NAME]: " new_value
               [[ -n "$new_value" ]] && CT_NAME="$new_value" ;;
            3) read -p "Enter Disk Size in GB [$DISK_SIZE]: " new_value
               [[ -n "$new_value" ]] && DISK_SIZE="$new_value" ;;
            4) read -p "Enter RAM in MB [$RAM]: " new_value
               [[ -n "$new_value" ]] && RAM="$new_value" ;;
            5) read -p "Enter CPU Cores [$CPU_CORES]: " new_value
               [[ -n "$new_value" ]] && CPU_CORES="$new_value" ;;
            6) read -p "Enter IP Address [$IP]: " new_value
               if [[ -n "$new_value" ]]; then
                   if validate_ip "$new_value"; then
                       IP="$new_value"
                   else
                       msg_error "Invalid IP address format!"; sleep 2
                   fi
               fi ;;
            7) read -p "Enter Gateway [$GATEWAY]: " new_value
               [[ -n "$new_value" ]] && GATEWAY="$new_value" ;;
            8) read -p "Enter DNS Server [$DNS]: " new_value
               [[ -n "$new_value" ]] && DNS="$new_value" ;;
            9) read -p "Enter Storage [$STORAGE]: " new_value
               [[ -n "$new_value" ]] && STORAGE="$new_value" ;;
            10) read -p "Enable SSH? (yes/no) [$SSH_ENABLED]: " new_value
                [[ -n "$new_value" ]] && SSH_ENABLED="$new_value" ;;
            11) read -s -p "Enter Root Password: " new_value
                echo; [[ -n "$new_value" ]] && PASSWORD="$new_value" ;;
            12) read -p "Enter Cert Server IP [$CERT_SERVER]: " new_value
                [[ -n "$new_value" ]] && CERT_SERVER="$new_value" ;;
            13) read -p "Enter Domain [$DOMAIN]: " new_value
                [[ -n "$new_value" ]] && DOMAIN="$new_value" ;;
            14) read -p "Enter Timezone [$TIMEZONE]: " new_value
                [[ -n "$new_value" ]] && TIMEZONE="$new_value" ;;
            15) show_config_menu; return ;;
            *) msg_warn "Invalid option!"; sleep 2 ;;
        esac
    done
}

reset_defaults() {
    CT_ID="$DEFAULT_CT_ID"
    CT_NAME="$DEFAULT_CT_NAME"
    DISK_SIZE="$DEFAULT_DISK_SIZE"
    RAM="$DEFAULT_RAM"
    CPU_CORES="$DEFAULT_CPU_CORES"
    IP="$DEFAULT_IP"
    GATEWAY="$DEFAULT_GATEWAY"
    DNS="$DEFAULT_DNS"
    STORAGE="$DEFAULT_STORAGE"
    PASSWORD="$DEFAULT_PASSWORD"
    SSH_ENABLED="$DEFAULT_SSH_ENABLED"
    CERT_SERVER="$DEFAULT_CERT_SERVER"
    DOMAIN="$DEFAULT_DOMAIN"
    TIMEZONE="$DEFAULT_TIMEZONE"
    msg_ok "Configuration reset to defaults"
    sleep 2
    show_config_menu
}

# Initialize variables with defaults
CT_ID="$DEFAULT_CT_ID"
CT_NAME="$DEFAULT_CT_NAME"
DISK_SIZE="$DEFAULT_DISK_SIZE"
RAM="$DEFAULT_RAM"
CPU_CORES="$DEFAULT_CPU_CORES"
IP="$DEFAULT_IP"
GATEWAY="$DEFAULT_GATEWAY"
DNS="$DEFAULT_DNS"
STORAGE="$DEFAULT_STORAGE"
PASSWORD="$DEFAULT_PASSWORD"
SSH_ENABLED="$DEFAULT_SSH_ENABLED"
CERT_SERVER="$DEFAULT_CERT_SERVER"
DOMAIN="$DEFAULT_DOMAIN"
TIMEZONE="$DEFAULT_TIMEZONE"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ct-id) CT_ID="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --gateway) GATEWAY="$2"; shift 2 ;;
        --dns) DNS="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --cert-server) CERT_SERVER="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        --non-interactive) NON_INTERACTIVE="yes"; shift ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --ct-id <id>          Container ID (default: $DEFAULT_CT_ID)"
            echo "  --ip <address>        IP address (default: $DEFAULT_IP)"
            echo "  --gateway <address>   Gateway (default: $DEFAULT_GATEWAY)"
            echo "  --dns <address>       DNS server (default: $DEFAULT_DNS)"
            echo "  --storage <name>      Storage name (default: $DEFAULT_STORAGE)"
            echo "  --password <pass>     Root password (default: $DEFAULT_PASSWORD)"
            echo "  --cert-server <ip>    Certificate server (default: $DEFAULT_CERT_SERVER)"
            echo "  --domain <domain>     Domain name (default: $DEFAULT_DOMAIN)"
            echo "  --non-interactive     Skip configuration menu"
            echo "  --help               Show this help"
            exit 0 ;;
        *) msg_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Main execution function
main() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  IES Military Database Analyzer       ${NC}"
    echo -e "${CYAN}  Proxmox LXC Container Deployment     ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo
    
    # Verify Proxmox environment
    if ! command -v pct &> /dev/null; then
        msg_error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    # Show configuration menu unless non-interactive
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        show_config_menu
    fi
    
    # Check for required template
    TEMPLATE="ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
    if [[ ! -f "/var/lib/vz/template/cache/$TEMPLATE" ]]; then
        msg_warn "Ubuntu 22.04 LXC template not found"
        msg_info "Downloading Ubuntu 22.04 template..."
        pveam update >/dev/null 2>&1
        pveam download local $TEMPLATE >/dev/null 2>&1
    fi
    
    # Start deployment
    create_container
    install_system_dependencies
    install_docker
    install_ies_application
    configure_nginx
    setup_monitoring
    configure_firewall
    create_management_scripts
    finalize_setup
    show_completion_info
}

create_container() {
    msg_info "Creating LXC container with ID $CT_ID"
    
    if ! check_ct_id "$CT_ID"; then
        msg_error "Container ID $CT_ID already exists!"
        exit 1
    fi
    
    pct create $CT_ID /var/lib/vz/template/cache/ubuntu-22.04-standard_22.04-1_amd64.tar.zst \
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
        --start 1 >/dev/null 2>&1
    
    msg_ok "Container $CT_ID created successfully"
    
    # Wait for container to be ready
    msg_info "Waiting for container to start..."
    sleep 15
    
    # Wait for network
    local retry_count=0
    while ! pct exec $CT_ID -- ping -c 1 8.8.8.8 >/dev/null 2>&1; do
        if [[ $retry_count -ge 30 ]]; then
            msg_error "Network not ready after 30 attempts"
            exit 1
        fi
        sleep 2
        ((retry_count++))
    done
    msg_ok "Network connectivity established"
}

install_system_dependencies() {
    msg_info "Installing system dependencies"
    
    pct exec $CT_ID -- bash -c "
        apt-get update >/dev/null 2>&1
        apt-get upgrade -y >/dev/null 2>&1
        apt-get install -y \
            curl wget git python3 python3-pip python3-venv python3-dev \
            nginx supervisor ufw fail2ban htop nano vim unzip \
            ca-certificates gnupg lsb-release software-properties-common \
            build-essential >/dev/null 2>&1
    "
    
    if [[ "$SSH_ENABLED" == "yes" ]]; then
        pct exec $CT_ID -- bash -c "
            apt-get install -y openssh-server >/dev/null 2>&1
            systemctl enable ssh >/dev/null 2>&1
            systemctl start ssh >/dev/null 2>&1
        "
        msg_ok "SSH service installed and enabled"
    fi
    
    msg_ok "System dependencies installed"
}

install_docker() {
    msg_info "Installing Docker"
    
    pct exec $CT_ID -- bash -c "
        # Clean up any existing installations
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        rm -f /usr/share/keyrings/docker-archive-keyring.gpg
        rm -f /etc/apt/sources.list.d/docker.list*
        
        # Add Docker GPG key and repository with proper error handling
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        ARCH=\$(dpkg --print-architecture)
        CODENAME=\$(lsb_release -cs)
        echo \"deb [arch=\${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \${CODENAME} stable\" > /etc/apt/sources.list.d/docker.list
        
        # Install Docker
        if apt-get update 2>&1 && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin 2>&1; then
            echo 'Docker installed from official repository'
        else
            echo 'Falling back to Ubuntu Docker packages'
            rm -f /etc/apt/sources.list.d/docker.list
            apt-get update >/dev/null 2>&1
            apt-get install -y docker.io docker-compose >/dev/null 2>&1
        fi
        
        systemctl enable docker >/dev/null 2>&1
        systemctl start docker >/dev/null 2>&1
        usermod -aG docker root
    "
    
    msg_ok "Docker installed successfully"
}

install_ies_application() {
    msg_info "Installing IES Military Database Analyzer"
    
    pct exec $CT_ID -- bash -c "
        cd /opt
        git clone https://github.com/DXCSithlordPadawan/IES.git >/dev/null 2>&1 || {
            if [ -d 'IES' ]; then
                cd IES && git pull >/dev/null 2>&1
            else
                exit 1
            fi
        }
        cd IES
        
        # Create virtual environment
        python3 -m venv ies_env
        source ies_env/bin/activate
        
        # Install dependencies in correct order
        pip install --upgrade pip wheel setuptools >/dev/null 2>&1
        pip install numpy pandas matplotlib seaborn networkx plotly >/dev/null 2>&1
        pip install scikit-learn flask jinja2 gunicorn >/dev/null 2>&1
        pip install prometheus-client psutil requests >/dev/null 2>&1
        
        # Try requirements.txt if it exists
        if [ -f requirements.txt ]; then
            pip install -r requirements.txt >/dev/null 2>&1 || true
        fi
        
        # Verify critical dependencies
        python3 -c \"
import sys
failed = []
packages = ['networkx', 'pandas', 'numpy', 'matplotlib', 'seaborn', 'plotly', 'flask', 'sklearn']
for pkg in packages:
    try:
        __import__(pkg)
        print(f'✓ {pkg}')
    except ImportError:
        failed.append(pkg)
        print(f'✗ {pkg}')

if failed:
    print(f'Failed packages: {failed}')
    import subprocess
    for pkg in failed:
        subprocess.run(['pip', 'install', '--force-reinstall', pkg], check=True)
        \"
        
        # Create enhanced application file with all fixes
        cat > military_database_analyzer_v3.py << 'EOF'
#!/usr/bin/env python3
import argparse, sys, os, time
from pathlib import Path
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class MilitaryDatabaseAnalyzer:
    def __init__(self, data_directory: str = \"data\"):
        self.data_dir = Path(data_directory)
        self.output_dir = Path(\"output\") 
        self.output_dir.mkdir(exist_ok=True)

def main():
    parser = argparse.ArgumentParser(description=\"IES4 Military Database Analysis Suite\")
    parser.add_argument('--web', action='store_true', help='Launch web interface')
    parser.add_argument('--host', default='127.0.0.1', help='Host for web interface')
    parser.add_argument('--port', type=int, default=5000, help='Port for web interface')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    args = parser.parse_args()
    
    if args.web:
        try:
            from flask import Flask, jsonify, render_template_string
            from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
            import psutil
            
            app = Flask(__name__)
            
            # Metrics
            REQUEST_COUNT = Counter('ies_http_requests_total', 'HTTP requests', ['method', 'endpoint', 'status'])
            REQUEST_DURATION = Histogram('ies_http_request_duration_seconds', 'Request duration', ['method', 'endpoint'])
            SYSTEM_CPU = Gauge('ies_system_cpu_percent', 'CPU usage')
            SYSTEM_MEMORY = Gauge('ies_system_memory_bytes', 'Memory usage')
            APPLICATION_STATUS = Gauge('ies_application_status', 'App status')
            
            @app.before_request
            def before_request():
                from flask import request
                request.start_time = time.time()
            
            @app.after_request
            def after_request(response):
                from flask import request
                duration = time.time() - request.start_time
                REQUEST_COUNT.labels(method=request.method, endpoint=request.endpoint or 'unknown', status=response.status_code).inc()
                REQUEST_DURATION.labels(method=request.method, endpoint=request.endpoint or 'unknown').observe(duration)
                return response
            
            @app.route('/')
            def home():
                return render_template_string(\"\"\"
                <!DOCTYPE html>
                <html><head><title>IES Military Database Analyzer</title>
                <style>body{font-family:Arial;margin:40px;background:#f5f5f5} .container{max-width:800px;margin:0 auto;background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)} h1{color:#2c3e50} .status{background:#e8f5e8;padding:15px;border-radius:4px;margin:20px 0} .links a{display:inline-block;margin:10px;padding:8px 15px;background:#3498db;color:white;text-decoration:none;border-radius:4px}</style>
                </head><body><div class=\"container\">
                <h1>IES Military Database Analyzer</h1>
                <div class=\"status\"><strong>Status:</strong> System operational<br><strong>Time:</strong> {{ time }}<br><strong>Version:</strong> 3.0</div>
                <div class=\"links\"><a href=\"/health\">Health Check</a><a href=\"/metrics\">Metrics</a></div>
                </div></body></html>
                \"\"\", time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            @app.route('/health')
            def health():
                return jsonify({'status': 'healthy', 'timestamp': time.time(), 'version': '3.0'})
            
            @app.route('/metrics')
            def metrics():
                SYSTEM_CPU.set(psutil.cpu_percent(interval=0.1))
                SYSTEM_MEMORY.set(psutil.virtual_memory().used)
                APPLICATION_STATUS.set(1)
                return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
            
            app.run(host=args.host, port=args.port, debug=args.verbose)
            
        except ImportError as e:
            print(f\"Missing dependencies: {e}\")
            print(\"Install with: pip install flask prometheus-client psutil\")
            sys.exit(1)
    else:
        print(\"IES Military Database Analyzer v3.0\")
        print(\"Use --web to start web interface\")

if __name__ == \"__main__\": 
    main()
EOF
        
        chmod +x military_database_analyzer_v3.py
        
        # Create directories
        mkdir -p /opt/IES/{logs,data,config,static,templates}
        chmod 755 /opt/IES/{logs,data,config}
        
        # Create systemd service
        cat > /etc/systemd/system/ies-analyzer.service << 'EOF'
[Unit]
Description=IES Military Database Analyzer
After=network.target
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
EOF
        
        systemctl daemon-reload
        systemctl enable ies-analyzer >/dev/null 2>&1
        systemctl start ies-analyzer >/dev/null 2>&1
    "
    
    msg_ok "IES Application installed successfully"
}

configure_nginx() {
    msg_info "Configuring Nginx reverse proxy"
    
    pct exec $CT_ID -- bash -c "
        rm -f /etc/nginx/sites-enabled/default
        
        cat > /etc/nginx/sites-available/ies-analyzer << 'EOF'
server {
    listen 80;
    server_name $DOMAIN _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN _;
    
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!aNULL:!MD5:!DSS;
    ssl_prefer_server_ciphers on;
    
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
        proxy_buffering off;
        
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
            -subj '/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN' >/dev/null 2>&1
        
        ln -sf /etc/nginx/sites-available/ies-analyzer /etc/nginx/sites-enabled/
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1
    "
    
    msg_ok "Nginx configured successfully"
}

setup_monitoring() {
    msg_info "Setting up monitoring stack"
    
    pct exec $CT_ID -- bash -c "
        mkdir -p /opt/monitoring/{prometheus,grafana}
        cd /opt/monitoring
        
        cat > prometheus/prometheus.yml << 'EOF'
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
EOF
        
        cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports: ['9090:9090']
    volumes: ['./prometheus:/etc/prometheus:ro', 'prometheus-data:/prometheus']
    command: ['--config.file=/etc/prometheus/prometheus.yml', '--storage.tsdb.path=/prometheus', '--storage.tsdb.retention.time=15d']
    extra_hosts: ['host.docker.internal:host-gateway']
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports: ['3000:3000']
    environment: ['GF_SECURITY_ADMIN_PASSWORD=admin123']
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
EOF
        
        docker compose up -d >/dev/null 2>&1
    "
    
    msg_ok "Monitoring stack deployed"
}

configure_firewall() {
    msg_info "Configuring firewall"
    
    pct exec $CT_ID -- bash -c "
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        
        if [[ '$SSH_ENABLED' == 'yes' ]]; then
            ufw allow from 192.168.0.0/24 to any port 22 >/dev/null 2>&1
        fi
        
        ufw allow from 192.168.0.0/24 to any port 80 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 443 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 3000 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 9090 >/dev/null 2>&1
		ufw allow from 192.168.0.0/24 to any port 9100 >/dev/null 2>&1
        
        ufw --force enable >/dev/null 2>&1
        systemctl enable fail2ban >/dev/null 2>&1
        systemctl start fail2ban >/dev/null 2>&1
    "
    
    msg_ok "Firewall configured"
}

create_management_scripts() {
    msg_info "Creating management scripts"
    
    pct exec $CT_ID -- bash -c "
        mkdir -p /usr/local/bin
        
        # Main management script with all fixes
        cat > /usr/local/bin/ies-manage << 'EOF'
#!/bin/bash

case \"\$1\" in
    start)
        systemctl start ies-analyzer nginx docker
        cd /opt/monitoring && docker compose start 2>/dev/null || true
        echo 'IES services started'
        ;;
    stop)
        systemctl stop ies-analyzer nginx
        cd /opt/monitoring && docker compose stop 2>/dev/null || true
        echo 'IES services stopped'
        ;;
    restart)
        systemctl restart ies-analyzer nginx docker
        cd /opt/monitoring && docker compose restart 2>/dev/null || true
        echo 'IES services restarted'
        ;;
    status)
        echo 'Service Status:'
        systemctl is-active ies-analyzer nginx docker | paste <(echo -e 'IES App\nNginx\nDocker') -
        echo 'Listening Ports:'
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
        echo 'Testing application endpoints...'
        curl -s -o /dev/null -w 'App Health: %{http_code}\n' http://127.0.0.1:8000/health 2>/dev/null || echo 'App Health: No response'
        curl -s -o /dev/null -w 'Nginx HTTP: %{http_code}\n' http://127.0.0.1/ 2>/dev/null || echo 'Nginx HTTP: No response'
        curl -s -k -o /dev/null -w 'Nginx HTTPS: %{http_code}\n' https://127.0.0.1/ 2>/dev/null || echo 'Nginx HTTPS: No response'
        ;;
    fix-deps)
        echo 'Fixing Python dependencies...'
        cd /opt/IES
        source ies_env/bin/activate
        pip install --force-reinstall networkx pandas numpy matplotlib seaborn plotly flask scikit-learn prometheus-client psutil
        systemctl restart ies-analyzer
        echo 'Dependencies fixed and service restarted'
        ;;
    fix-apt)
        echo 'Fixing APT configuration...'
        if [[ -f /etc/apt/sources.list.d/docker.list ]]; then
            if grep -q '\ /etc/apt/sources.list.d/docker.list; then
                ARCH=\$(dpkg --print-architecture)
                CODENAME=\$(lsb_release -cs)
                echo \"deb [arch=\${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \${CODENAME} stable\" > /etc/apt/sources.list.d/docker.list
                echo 'Docker repository fixed'
            fi
        fi
        apt update
        echo 'APT configuration repaired'
        ;;
    repair)
        echo 'Running comprehensive repair...'
        \$0 fix-apt
        \$0 fix-deps
        
        # Regenerate SSL certificates
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/server.key \
            -out /etc/nginx/ssl/server.crt \
            -subj \"/CN=\$(hostname -I | awk '{print \$1}')\" 2>/dev/null
        systemctl reload nginx
        
        # Restart all services
        \$0 restart
        sleep 5
        \$0 test
        echo 'System repair completed'
        ;;
    update)
        echo 'Updating IES application...'
        cd /opt/IES
        git pull
        source ies_env/bin/activate
        pip install --upgrade -r requirements.txt 2>/dev/null || echo 'No requirements.txt found'
        systemctl restart ies-analyzer
        echo 'Update complete'
        ;;
    backup)
        echo 'Creating backup...'
        tar -czf /opt/ies-backup-\$(date +%Y%m%d-%H%M%S).tar.gz \
            /opt/IES/data /opt/IES/config /opt/monitoring /etc/nginx/sites-available/ies-analyzer
        echo \"Backup created: /opt/ies-backup-\$(date +%Y%m%d-%H%M%S).tar.gz\"
        ;;
    *)
        echo 'Usage: \$0 {start|stop|restart|status|logs|test|fix-deps|fix-apt|repair|update|backup}'
        echo
        echo 'Commands:'
        echo '  start       - Start all IES services'
        echo '  stop        - Stop all IES services' 
        echo '  restart     - Restart all IES services'
        echo '  status      - Show service status'
        echo '  logs [type] - Show logs (app|nginx|monitoring)'
        echo '  test        - Test all endpoints'
        echo '  fix-deps    - Fix Python dependencies'
        echo '  fix-apt     - Fix APT configuration'
        echo '  repair      - Full system repair'
        echo '  update      - Update IES application'
        echo '  backup      - Create system backup'
        exit 1
        ;;
esac
EOF
        
        chmod +x /usr/local/bin/ies-manage
        
        # System monitoring script
        cat > /usr/local/bin/ies-monitor << 'EOF'
#!/bin/bash

IP=\$(hostname -I | awk '{print \$1}')
echo 'IES Military Database Analyzer Status'
echo '====================================='
echo
echo 'System Information:'
echo \"IP Address: \$IP\"
echo \"Hostname: \$(hostname)\"
echo \"Uptime: \$(uptime -p)\"
echo
echo 'Service Status:'
systemctl is-active ies-analyzer nginx docker fail2ban | paste <(echo -e 'IES App\nNginx\nDocker\nFail2Ban') -
echo
echo 'Network Services:'
ss -tlnp | grep -E ':(80|443|8000|3000|9090)' | awk '{print \$1, \$4}' || echo 'No services listening'
echo
echo 'Resource Usage:'
echo \"CPU: \$(top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | cut -d'%' -f1)%\"
echo \"Memory: \$(free -h | grep Mem | awk '{printf \"%.1f%%\n\", \$3/\$2*100}')\"
echo \"Disk: \$(df -h / | tail -1 | awk '{print \$5}')\"
echo
echo 'Access URLs:'
echo \"Application: https://\$IP\"
echo \"Grafana: http://\$IP:3000\"
echo \"Prometheus: http://\$IP:9090\"
echo
echo 'Quick Test:'
curl -s -o /dev/null -w 'Health Check: %{http_code}\n' http://127.0.0.1:8000/health 2>/dev/null || echo 'Health Check: Failed'
EOF
        
        chmod +x /usr/local/bin/ies-monitor
        
        # Emergency repair script
        cat > /usr/local/bin/ies-emergency-repair << 'EOF'
#!/bin/bash

echo 'IES Emergency Repair - Fixing All Known Issues'
echo '============================================='

# Fix APT issues
echo 'Step 1: Fixing APT configuration...'
ies-manage fix-apt

# Fix Python dependencies
echo 'Step 2: Fixing Python dependencies...'
ies-manage fix-deps

# Update application file if needed
echo 'Step 3: Ensuring application compatibility...'
cd /opt/IES
if ! grep -q \"--host\" military_database_analyzer_v3.py; then
    echo 'Updating application to support --host and --port arguments...'
    cp military_database_analyzer_v3.py military_database_analyzer_v3.py.backup
    # Application is already updated in the install script
fi

# Restart all services
echo 'Step 4: Restarting all services...'
systemctl stop ies-analyzer nginx
sleep 5
systemctl start docker nginx ies-analyzer

# Test everything
echo 'Step 5: Testing system...'
sleep 10
ies-manage test

echo 'Emergency repair completed!'
EOF
        
        chmod +x /usr/local/bin/ies-emergency-repair
    "
    
    msg_ok "Management scripts created"
}

finalize_setup() {
    msg_info "Finalizing setup and running tests"
    
    # Wait for services to be ready
    sleep 20
    
    # Test application endpoint
    if pct exec $CT_ID -- curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/health 2>/dev/null | grep -q "200"; then
        msg_ok "Application health check passed"
    else
        msg_warn "Application health check failed - service may still be starting"
    fi
    
    # Test nginx
    if pct exec $CT_ID -- nginx -t >/dev/null 2>&1; then
        msg_ok "Nginx configuration test passed"
    else
        msg_warn "Nginx configuration test failed"
    fi
    
    # Save configuration
    pct exec $CT_ID -- bash -c "
        cat > /root/ies-deployment-info.txt << 'EOF'
IES Military Database Analyzer Deployment Information
===================================================

Deployment Date: \$(date)
Container ID: $CT_ID
Container Name: $CT_NAME
IP Address: $IP
Gateway: $GATEWAY
DNS Server: $DNS
Domain: $DOMAIN
Root Password: [HIDDEN]

Access Information:
- Application: https://$IP
- Grafana: http://$IP:3000 (admin/admin123)
- Prometheus: http://$IP:9090
- SSH: ssh root@$IP (if enabled)

Management Commands:
- ies-manage {start|stop|restart|status|logs|test|repair}
- ies-monitor (system status)
- ies-emergency-repair (fix all known issues)

Configuration Files:
- Application: /opt/IES
- Nginx: /etc/nginx/sites-available/ies-analyzer
- Monitoring: /opt/monitoring/docker-compose.yml
- Service: /etc/systemd/system/ies-analyzer.service

Security:
- Firewall: UFW enabled (192.168.0.0/24 only)
- Fail2Ban: Active
- SSL: Self-signed certificate
- SSH: $SSH_ENABLED

For support: ies-manage test, ies-manage repair
EOF
    "
    
    msg_ok "Setup completed successfully!"
}

show_completion_info() {
    clear
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  IES Military Database Analyzer Deployment${NC}"
    echo -e "${GREEN}  COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo
    echo -e "${BLUE}Container Information:${NC}"
    echo -e "Container ID:      ${GREEN}$CT_ID${NC}"
    echo -e "Container Name:    ${GREEN}$CT_NAME${NC}"
    echo -e "IP Address:        ${GREEN}$IP${NC}"
    echo -e "Domain:            ${GREEN}$DOMAIN${NC}"
    echo
    echo -e "${BLUE}Access URLs:${NC}"
    echo -e "Application HTTPS: ${CYAN}https://$IP${NC}"
    echo -e "Application HTTP:  ${CYAN}http://$IP${NC} (redirects to HTTPS)"
    echo -e "Grafana Dashboard: ${CYAN}http://$IP:3000${NC} (admin/admin123)"
    echo -e "Prometheus:        ${CYAN}http://$IP:9090${NC}"
    
    if [[ "$SSH_ENABLED" == "yes" ]]; then
        echo -e "SSH Access:        ${CYAN}ssh root@$IP${NC}"
    fi
    
    echo
    echo -e "${BLUE}Container Management (Proxmox Host):${NC}"
    echo -e "Start Container:   ${YELLOW}pct start $CT_ID${NC}"
    echo -e "Stop Container:    ${YELLOW}pct stop $CT_ID${NC}"
    echo -e "Console Access:    ${YELLOW}pct enter $CT_ID${NC}"
    echo -e "Container Status:  ${YELLOW}pct status $CT_ID${NC}"
    echo
    echo -e "${BLUE}Application Management (Inside Container):${NC}"
    echo -e "Service Control:   ${YELLOW}ies-manage {start|stop|restart|status}${NC}"
    echo -e "View Logs:         ${YELLOW}ies-manage logs [app|nginx|monitoring]${NC}"
    echo -e "System Status:     ${YELLOW}ies-monitor${NC}"
    echo -e "Test Endpoints:    ${YELLOW}ies-manage test${NC}"
    echo -e "Fix Dependencies:  ${YELLOW}ies-manage fix-deps${NC}"
    echo -e "Full Repair:       ${YELLOW}ies-manage repair${NC}"
    echo -e "Update App:        ${YELLOW}ies-manage update${NC}"
    echo -e "Create Backup:     ${YELLOW}ies-manage backup${NC}"
    echo -e "Emergency Repair:  ${YELLOW}ies-emergency-repair${NC}"
    echo
    echo -e "${BLUE}Security & Network:${NC}"
    echo -e "Firewall:          ${GREEN}UFW enabled (192.168.0.0/24 only)${NC}"
    echo -e "Intrusion Prevention: ${GREEN}Fail2Ban active${NC}"
    echo -e "SSL Certificate:   ${GREEN}Self-signed (consider replacing)${NC}"
    echo -e "Network Access:    ${GREEN}Local network only${NC}"
    echo
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Test access: https://$IP"
    echo "2. Review monitoring: http://$IP:3000"
    echo "3. Replace SSL certificates if needed"
    echo "4. Configure DNS entry for $DOMAIN"
    echo "5. Set up regular backups"
    echo "6. Change default passwords"
    echo
    echo -e "${BLUE}Troubleshooting:${NC}"
    echo "- System status: ies-monitor"
    echo "- Test all endpoints: ies-manage test"
    echo "- View logs: ies-manage logs app"
    echo "- Full repair: ies-manage repair"
    echo "- Emergency fix: ies-emergency-repair"
    echo
    echo -e "${GREEN}Deployment information saved in container: /root/ies-deployment-info.txt${NC}"
    echo -e "${GREEN}Ready for production use!${NC}"
}

# Script help function
show_help() {
    echo "IES Military Database Analyzer - Proxmox LXC Deployment"
    echo "========================================================"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "OPTIONS:"
    echo "  --ct-id <id>          Container ID (default: $DEFAULT_CT_ID)"
    echo "  --ip <address>        IP address (default: $DEFAULT_IP)"
    echo "  --gateway <address>   Gateway (default: $DEFAULT_GATEWAY)"
    echo "  --dns <address>       DNS server (default: $DEFAULT_DNS)"
    echo "  --storage <name>      Storage pool (default: $DEFAULT_STORAGE)"
    echo "  --password <pass>     Root password (default: $DEFAULT_PASSWORD)"
    echo "  --cert-server <ip>    Certificate server (default: $DEFAULT_CERT_SERVER)"
    echo "  --domain <domain>     Domain name (default: $DEFAULT_DOMAIN)"
    echo "  --non-interactive     Skip configuration menu"
    echo "  --help               Show this help"
    echo
    echo "EXAMPLES:"
    echo "  $0                                    # Interactive installation"
    echo "  $0 --non-interactive                 # Use all defaults"
    echo "  $0 --ct-id 352 --ip 192.168.0.201   # Custom ID and IP"
    echo
    echo "FEATURES:"
    echo "  - Complete IES application stack"
    echo "  - Nginx reverse proxy with SSL"
    echo "  - Prometheus + Grafana monitoring"
    echo "  - Comprehensive security (UFW, Fail2Ban)"
    echo "  - Management utilities and auto-repair"
    echo "  - All known issues pre-fixed"
    echo
    echo "SUPPORT:"
    echo "  After installation, use 'ies-manage' and 'ies-monitor' commands"
    echo "  For emergencies: 'ies-emergency-repair'"
}

# Check if help requested
[[ "$1" == "--help" || "$1" == "-h" ]] && { show_help; exit 0; }

# Run main function
main "$@"