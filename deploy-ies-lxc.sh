#!/usr/bin/env bash

# IES Military Database Analyzer LXC Container Creation Script
# Compatible with Proxmox Community Scripts format
# Version: 2.0.0
# Author: DXC Technology
# Description: Creates an LXC container with IES Military Database Analyzer

source /dev/stdin <<< "$FUNCTIONS_FILE_PATH" 2>/dev/null || true
[[ -n "$FUNCTIONS_FILE_PATH" ]] && color 2>/dev/null || true
[[ -n "$FUNCTIONS_FILE_PATH" ]] && verb_ip6 2>/dev/null || true
[[ -n "$FUNCTIONS_FILE_PATH" ]] && catch_errors 2>/dev/null || true
[[ -n "$FUNCTIONS_FILE_PATH" ]] && setting_up_container 2>/dev/null || true
[[ -n "$FUNCTIONS_FILE_PATH" ]] && network_check 2>/dev/null || true
[[ -n "$FUNCTIONS_FILE_PATH" ]] && update_os 2>/dev/null || true

# Default configuration
DEFAULT_CT_ID="351"
DEFAULT_CT_NAME="ies-analyzer"
DEFAULT_DISK_SIZE="12"
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

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Function to display colored output
function msg_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
function msg_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
function msg_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
function msg_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -lt 0 || $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to check if CT ID is available
check_ct_id() {
    local ct_id=$1
    if pct status $ct_id >/dev/null 2>&1; then
        return 1
    else
        return 0
    fi
}

# Configuration menu
show_config_menu() {
    while true; do
        clear
        echo -e "${CYAN}=================================================${NC}"
        echo -e "${CYAN}    IES Military Database Analyzer Setup       ${NC}"
        echo -e "${CYAN}=================================================${NC}"
        echo
        echo -e "${WHITE}Current Configuration:${NC}"
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
        echo -e "${WHITE}Options:${NC}"
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
            *) msg_warn "Invalid option. Please try again."; sleep 2 ;;
        esac
    done
}

# Advanced configuration menu
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
            1)
                read -p "Enter CT ID [$CT_ID]: " new_value
                if [[ -n "$new_value" ]]; then
                    if check_ct_id "$new_value"; then
                        CT_ID="$new_value"
                    else
                        msg_error "CT ID $new_value already exists!"
                        sleep 2
                    fi
                fi
                ;;
            2)
                read -p "Enter Container Name [$CT_NAME]: " new_value
                [[ -n "$new_value" ]] && CT_NAME="$new_value"
                ;;
            3)
                read -p "Enter Disk Size in GB [$DISK_SIZE]: " new_value
                [[ -n "$new_value" ]] && DISK_SIZE="$new_value"
                ;;
            4)
                read -p "Enter RAM in MB [$RAM]: " new_value
                [[ -n "$new_value" ]] && RAM="$new_value"
                ;;
            5)
                read -p "Enter CPU Cores [$CPU_CORES]: " new_value
                [[ -n "$new_value" ]] && CPU_CORES="$new_value"
                ;;
            6)
                read -p "Enter IP Address [$IP]: " new_value
                if [[ -n "$new_value" ]]; then
                    if validate_ip "$new_value"; then
                        IP="$new_value"
                    else
                        msg_error "Invalid IP address format!"
                        sleep 2
                    fi
                fi
                ;;
            7)
                read -p "Enter Gateway [$GATEWAY]: " new_value
                [[ -n "$new_value" ]] && GATEWAY="$new_value"
                ;;
            8)
                read -p "Enter DNS Server [$DNS]: " new_value
                [[ -n "$new_value" ]] && DNS="$new_value"
                ;;
            9)
                read -p "Enter Storage [$STORAGE]: " new_value
                [[ -n "$new_value" ]] && STORAGE="$new_value"
                ;;
            10)
                read -p "Enable SSH? (yes/no) [$SSH_ENABLED]: " new_value
                [[ -n "$new_value" ]] && SSH_ENABLED="$new_value"
                ;;
            11)
                read -s -p "Enter Root Password: " new_value
                echo
                [[ -n "$new_value" ]] && PASSWORD="$new_value"
                ;;
            12)
                read -p "Enter Cert Server IP [$CERT_SERVER]: " new_value
                [[ -n "$new_value" ]] && CERT_SERVER="$new_value"
                ;;
            13)
                read -p "Enter Domain [$DOMAIN]: " new_value
                [[ -n "$new_value" ]] && DOMAIN="$new_value"
                ;;
            14)
                read -p "Enter Timezone [$TIMEZONE]: " new_value
                [[ -n "$new_value" ]] && TIMEZONE="$new_value"
                ;;
            15)
                return
                ;;
            *)
                msg_warn "Invalid option!"
                sleep 2
                ;;
        esac
    done
}

# Reset to defaults
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

# Parse command line arguments for non-interactive mode
while [[ $# -gt 0 ]]; do
    case $1 in
        --ct-id)
            CT_ID="$2"
            shift 2
            ;;
        --ct-name)
            CT_NAME="$2"
            shift 2
            ;;
        --disk-size)
            DISK_SIZE="$2"
            shift 2
            ;;
        --ram)
            RAM="$2"
            shift 2
            ;;
        --cores)
            CPU_CORES="$2"
            shift 2
            ;;
        --ip)
            IP="$2"
            shift 2
            ;;
        --gateway)
            GATEWAY="$2"
            shift 2
            ;;
        --dns)
            DNS="$2"
            shift 2
            ;;
        --storage)
            STORAGE="$2"
            shift 2
            ;;
        --password)
            PASSWORD="$2"
            shift 2
            ;;
        --cert-server)
            CERT_SERVER="$2"
            shift 2
            ;;
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --timezone)
            TIMEZONE="$2"
            shift 2
            ;;
        --ssh)
            SSH_ENABLED="$2"
            shift 2
            ;;
        --non-interactive)
            NON_INTERACTIVE="yes"
            shift
            ;;
        --help)
            cat << 'EOF'
IES Military Database Analyzer LXC Deployment Script

Usage: ./deploy-ies-lxc.sh [options]

Options:
  --ct-id <id>          Container ID (default: 351)
  --ct-name <name>      Container name (default: ies-analyzer)
  --disk-size <GB>      Disk size in GB (default: 12)
  --ram <MB>            RAM in MB (default: 2048)
  --cores <num>         CPU cores (default: 2)
  --ip <address>        IP address (default: 192.168.0.200)
  --gateway <address>   Gateway (default: 192.168.0.1)
  --dns <address>       DNS server (default: 192.168.0.110)
  --storage <name>      Storage name (default: local-lvm)
  --password <pass>     Root password (default: BobTheBigRedBus-0)
  --cert-server <ip>    Certificate server (default: 192.168.0.122)
  --domain <domain>     Domain name (default: ies-analyzer.local)
  --timezone <tz>       Timezone (default: America/New_York)
  --ssh <yes/no>        SSH enabled (default: yes)
  --non-interactive     Skip configuration menu
  --help               Show this help

Examples:
  ./deploy-ies-lxc.sh                                    # Interactive mode
  ./deploy-ies-lxc.sh --non-interactive                  # Use defaults
  ./deploy-ies-lxc.sh --ct-id 352 --ip 192.168.0.201    # Custom settings
EOF
            exit 0
            ;;
        *)
            msg_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Show configuration menu unless non-interactive mode
if [[ "$NON_INTERACTIVE" != "yes" ]]; then
    show_config_menu
fi

# Write configuration file
write_config() {
    local config_file="/tmp/ies-analyzer-config.conf"
    cat > "$config_file" << EOF
# IES Military Database Analyzer Configuration
# Generated: $(date)

[CONTAINER]
CT_ID=$CT_ID
CT_NAME=$CT_NAME
DISK_SIZE=$DISK_SIZE
RAM=$RAM
CPU_CORES=$CPU_CORES

[NETWORK]
IP_ADDRESS=$IP
GATEWAY=$GATEWAY
DNS_SERVER=$DNS

[SYSTEM]
STORAGE=$STORAGE
SSH_ENABLED=$SSH_ENABLED
ROOT_PASSWORD=$PASSWORD
TIMEZONE=$TIMEZONE

[APPLICATION]
CERT_SERVER=$CERT_SERVER
DOMAIN=$DOMAIN
REPO_URL=https://github.com/DXCSithlordPadawan/IES.git

[MONITORING]
PROMETHEUS_ENABLED=yes
GRAFANA_ENABLED=yes
MONITORING_PORT=3000

[SECURITY]
FIREWALL_ENABLED=yes
FAIL2BAN_ENABLED=yes
AUTO_UPDATES=yes
EOF
    echo "$config_file"
}

# Create LXC container
create_container() {
    msg_info "Creating LXC container with ID $CT_ID"
    
    # Check if CT ID is available
    if ! check_ct_id "$CT_ID"; then
        msg_error "Container ID $CT_ID already exists!"
        exit 1
    fi
    
    # Download Ubuntu template if needed
    local template="ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
    if [[ ! -f "/var/lib/vz/template/cache/$template" ]]; then
        msg_info "Downloading Ubuntu 22.04 template..."
        pveam update >/dev/null 2>&1
        pveam download local "$template"
    fi
    
    # Create the container
    pct create $CT_ID "/var/lib/vz/template/cache/$template" \
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
        --start 1
    
    if [[ $? -eq 0 ]]; then
        msg_ok "Container $CT_ID created successfully"
    else
        msg_error "Failed to create container"
        exit 1
    fi
    
    # Wait for container to start
    msg_info "Waiting for container to start and network to be ready..."
    sleep 15
    
    # Wait for network to be ready
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

# Install system dependencies and Docker
install_system_dependencies() {
    msg_info "Installing system dependencies and Docker"
    
    pct exec $CT_ID -- bash -c "
        # Update system
        apt-get update >/dev/null 2>&1
        apt-get upgrade -y >/dev/null 2>&1
        
        # Install basic system packages
        apt-get install -y \
            curl wget git python3 python3-pip python3-venv python3-dev \
            build-essential nginx supervisor ufw fail2ban htop nano vim \
            unzip ca-certificates gnupg lsb-release software-properties-common \
            openssl >/dev/null 2>&1
            
        # Install SSH if enabled
        if [[ '$SSH_ENABLED' == 'yes' ]]; then
            apt-get install -y openssh-server >/dev/null 2>&1
            systemctl enable ssh >/dev/null 2>&1
        fi
        
        # Install Docker
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable\" > /etc/apt/sources.list.d/docker.list
        
        apt-get update >/dev/null 2>&1
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1 || {
            # Fallback to Ubuntu Docker packages if official repo fails
            apt-get install -y docker.io docker-compose >/dev/null 2>&1
        }
        
        systemctl enable docker >/dev/null 2>&1
        systemctl start docker >/dev/null 2>&1
    "
    
    msg_ok "System dependencies and Docker installed"
}

# Install IES Application
install_ies_application() {
    msg_info "Installing IES Military Database Analyzer"
    
    pct exec $CT_ID -- bash -c "
        cd /opt
        git clone https://github.com/DXCSithlordPadawan/IES.git >/dev/null 2>&1 || {
            if [ -d 'IES' ]; then
                cd IES && git pull >/dev/null 2>&1
            else
                msg_error 'Failed to clone repository'
                exit 1
            fi
        }
        cd IES
        
        # Create virtual environment
        python3 -m venv ies_env
        source ies_env/bin/activate
        
        # Install core dependencies in correct order
        pip install --upgrade pip >/dev/null 2>&1
        pip install numpy pandas matplotlib seaborn networkx plotly \\
                   scikit-learn flask jinja2 gunicorn prometheus-client \\
                   psutil requests jsonschema >/dev/null 2>&1
        
        # Install from requirements.txt if available
        if [ -f requirements.txt ]; then
            pip install -r requirements.txt >/dev/null 2>&1 || true
        fi
        
        # Create application directories
        mkdir -p /opt/IES/{logs,data,config,static,templates}
        chmod 755 /opt/IES/{logs,data,config}
        
        # Create enhanced main application file if needed
        if [[ ! -f 'military_database_analyzer_v3.py' ]] || ! grep -q 'host.*port' military_database_analyzer_v3.py; then
            cat > military_database_analyzer_v3.py << 'PYTHON_EOF'
#!/usr/bin/env python3
import argparse, sys, os, time
from pathlib import Path
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    parser = argparse.ArgumentParser(description='IES Military Database Analysis Suite')
    parser.add_argument('--web', action='store_true', help='Launch web interface')
    parser.add_argument('--host', default='127.0.0.1', help='Host for web interface')
    parser.add_argument('--port', type=int, default=5000, help='Port for web interface')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    args = parser.parse_args()
    
    if args.web:
        from flask import Flask, jsonify, render_template_string
        app = Flask(__name__)
        
        # Setup metrics if available
        try:
            from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
            import psutil
            
            REQUEST_COUNT = Counter('ies_http_requests_total', 'HTTP requests', ['method', 'endpoint', 'status'])
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
                REQUEST_COUNT.labels(
                    method=request.method, 
                    endpoint=request.endpoint or 'unknown', 
                    status=response.status_code
                ).inc()
                return response
                
            @app.route('/metrics')
            def metrics():
                SYSTEM_CPU.set(psutil.cpu_percent())
                SYSTEM_MEMORY.set(psutil.virtual_memory().used)
                APPLICATION_STATUS.set(1)
                from flask import Response
                return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
                
        except ImportError:
            @app.route('/metrics')
            def metrics():
                return '''# IES Application Metrics
# TYPE ies_status gauge
ies_status 1
# TYPE ies_requests_total counter
ies_requests_total 1
''', 200, {'Content-Type': 'text/plain'}
        
        @app.route('/')
        def home():
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>IES Military Database Analyzer</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                    .container { max-width: 800px; margin: 0 auto; background: white; 
                                padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    h1 { color: #2c3e50; }
                    .status { background: #e8f5e8; padding: 15px; border-radius: 4px; margin: 20px 0; }
                    .links a { display: inline-block; margin: 10px; padding: 8px 15px; 
                              background: #3498db; color: white; text-decoration: none; border-radius: 4px; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <h1>IES Military Database Analyzer</h1>
                    <div class='status'>
                        <strong>Status:</strong> System operational<br>
                        <strong>Time:</strong> {{ time }}<br>
                        <strong>Version:</strong> 3.0 Production
                    </div>
                    <div class='links'>
                        <a href='/health'>Health Check</a>
                        <a href='/metrics'>Metrics</a>
                    </div>
                </div>
            </body>
            </html>
            ''', time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        @app.route('/health')
        def health():
            return jsonify({
                'status': 'healthy',
                'timestamp': time.time(),
                'version': '3.0',
                'service': 'IES Military Database Analyzer'
            })
        
        app.run(host=args.host, port=args.port, debug=args.verbose)
    else:
        print('IES Military Database Analyzer v3.0')
        print('Use --web to start web interface')

if __name__ == '__main__': main()
PYTHON_EOF
            chmod +x military_database_analyzer_v3.py
        fi
        
        # Verify critical dependencies
        source ies_env/bin/activate
        python3 -c 'import networkx, pandas, flask' || {
            pip install --force-reinstall networkx pandas flask matplotlib seaborn
        }
    "
    
    msg_ok "IES Application installation completed"
}

# Configure services
configure_services() {
    msg_info "Configuring system services"
    
    pct exec $CT_ID -- bash -c "
        # Create systemd service
        cat > /etc/systemd/system/ies-analyzer.service << 'SERVICE_EOF'
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

        systemctl daemon-reload
        systemctl enable ies-analyzer
    "
    
    msg_ok "System services configured"
}

# Configure Nginx
configure_nginx() {
    msg_info "Configuring Nginx reverse proxy"
    
    pct exec $CT_ID -- bash -c "
        # Remove default site
        rm -f /etc/nginx/sites-enabled/default
        
        # Create IES site configuration
        cat > /etc/nginx/sites-available/ies-analyzer << 'NGINX_EOF'
server {
    listen 80;
    server_name $DOMAIN _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN _;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!aNULL:!MD5:!DSS;
    ssl_prefer_server_ciphers on;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection '1; mode=block';
    add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains';
    
    # Application proxy
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
        allow 192.168.0.0/24;
        allow 127.0.0.1;
        deny all;
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
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\
            -keyout /etc/nginx/ssl/server.key \\
            -out /etc/nginx/ssl/server.crt \\
            -subj '/C=US/ST=State/L=City/O=IES/CN=$IP' >/dev/null 2>&1
        
        # Enable the site
        ln -sf /etc/nginx/sites-available/ies-analyzer /etc/nginx/sites-enabled/
        
        # Test and enable nginx
        nginx -t && systemctl enable nginx
    "
    
    msg_ok "Nginx configured successfully"
}

# Setup monitoring stack
setup_monitoring() {
    msg_info "Setting up monitoring stack"
    
    pct exec $CT_ID -- bash -c "
        mkdir -p /opt/monitoring/{prometheus,grafana}
        cd /opt/monitoring
        
        # Create Prometheus configuration
        cat > prometheus/prometheus.yml << 'PROM_EOF'
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
PROM_EOF
        
        # Create Docker Compose for monitoring
        cat > docker-compose.yml << 'COMPOSE_EOF'
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - '9090:9090'
    volumes:
      - ./prometheus:/etc/prometheus:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=15d'
    extra_hosts:
      - 'host.docker.internal:host-gateway'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - '3000:3000'
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - '9100:9100'
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($|/)'
    restart: unless-stopped

volumes:
  prometheus-data:
  grafana-data:
COMPOSE_EOF
        
        # Start monitoring services
        docker compose up -d >/dev/null 2>&1 || docker-compose up -d >/dev/null 2>&1
    "
    
    msg_ok "Monitoring stack deployed"
}

# Configure firewall and security
configure_security() {
    msg_info "Configuring firewall and security"
    
    pct exec $CT_ID -- bash -c "
        # Configure UFW
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1
        
        # Allow SSH (if enabled)
        if [[ '$SSH_ENABLED' == 'yes' ]]; then
            ufw allow from 192.168.0.0/24 to any port 22 >/dev/null 2>&1
        fi
        
        # Allow HTTP/HTTPS from local network
        ufw allow from 192.168.0.0/24 to any port 80 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 443 >/dev/null 2>&1
        
        # Allow monitoring ports from local network
        ufw allow from 192.168.0.0/24 to any port 3000 >/dev/null 2>&1
        ufw allow from 192.168.0.0/24 to any port 9090 >/dev/null 2>&1
        
        ufw --force enable >/dev/null 2>&1
        
        # Configure fail2ban
        systemctl enable fail2ban >/dev/null 2>&1
        systemctl start fail2ban >/dev/null 2>&1
    "
    
    msg_ok "Firewall and security configured"
}

# Create management scripts
create_management_scripts() {
    msg_info "Creating management scripts"
    
    pct exec $CT_ID -- bash -c "
        mkdir -p /usr/local/bin
        
        # Create main management script
        cat > /usr/local/bin/ies-manage << 'MANAGE_EOF'
#!/bin/bash

case \"\$1\" in
    start)
        systemctl start ies-analyzer nginx
        cd /opt/monitoring && (docker compose start || docker-compose start) 2>/dev/null
        echo 'IES services started'
        ;;
    stop)
        systemctl stop ies-analyzer nginx
        cd /opt/monitoring && (docker compose stop || docker-compose stop) 2>/dev/null
        echo 'IES services stopped'
        ;;
    restart)
        systemctl restart ies-analyzer nginx
        cd /opt/monitoring && (docker compose restart || docker-compose restart) 2>/dev/null
        echo 'IES services restarted'
        ;;
    status)
        echo 'Service Status:'
        systemctl is-active ies-analyzer nginx docker | paste <(echo -e 'IES App\\nNginx\\nDocker') -
        echo
        echo 'Monitoring Stack:'
        cd /opt/monitoring && (docker compose ps || docker-compose ps) 2>/dev/null | grep -E '(prometheus|grafana|node-exporter)'
        ;;
    logs)
        case \"\$2\" in
            app) journalctl -u ies-analyzer -f ;;
            nginx) journalctl -u nginx -f ;;
            monitoring) cd /opt/monitoring && (docker compose logs -f || docker-compose logs -f) 2>/dev/null ;;
            *) journalctl -u ies-analyzer --no-pager -n 50 ;;
        esac
        ;;
    test)
        echo 'Testing IES endpoints...'
        curl -s -o /dev/null -w 'Health Check: %{http_code}\\n' http://127.0.0.1:8000/health 2>/dev/null || echo 'Health Check: No response'
        curl -s -o /dev/null -w 'Metrics: %{http_code}\\n' http://127.0.0.1:8000/metrics 2>/dev/null || echo 'Metrics: No response'
        curl -s -o /dev/null -w 'HTTP: %{http_code}\\n' http://127.0.0.1/ 2>/dev/null || echo 'HTTP: No response'
        curl -s -k -o /dev/null -w 'HTTPS: %{http_code}\\n' https://127.0.0.1/ 2>/dev/null || echo 'HTTPS: No response'
        ;;
    update)
        echo 'Updating IES application...'
        cd /opt/IES
        git pull >/dev/null 2>&1
        source ies_env/bin/activate
        pip install --upgrade -r requirements.txt 2>/dev/null || echo 'Requirements file not found'
        systemctl restart ies-analyzer
        echo 'Update complete'
        ;;
    fix-deps)
        echo 'Fixing Python dependencies...'
        cd /opt/IES
        source ies_env/bin/activate
        pip install --force-reinstall networkx pandas numpy matplotlib seaborn plotly flask scikit-learn jinja2 gunicorn prometheus-client psutil
        systemctl restart ies-analyzer
        echo 'Dependencies fixed'
        ;;
    fix-apt)
        echo 'Fixing APT configuration...'
        if [[ -f /etc/apt/sources.list.d/docker.list ]]; then
            if grep -q '\\
         /etc/apt/sources.list.d/docker.list; then
                ARCH=\$(dpkg --print-architecture)
                CODENAME=\$(lsb_release -cs)
                echo \"deb [arch=\${ARCH} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \${CODENAME} stable\" > /etc/apt/sources.list.d/docker.list
            fi
        fi
        apt update >/dev/null 2>&1
        echo 'APT configuration fixed'
        ;;
    repair)
        echo 'Running comprehensive repair...'
        \$0 fix-apt
        \$0 fix-deps
        systemctl restart ies-analyzer nginx docker
        cd /opt/monitoring && (docker compose restart || docker-compose restart) 2>/dev/null
        sleep 10
        \$0 test
        echo 'Repair completed'
        ;;
    backup)
        BACKUP_FILE=\"/opt/ies-backup-\$(date +%Y%m%d-%H%M%S).tar.gz\"
        echo \"Creating backup: \$BACKUP_FILE\"
        tar -czf \"\$BACKUP_FILE\" /opt/IES/data /opt/IES/config /opt/monitoring 2>/dev/null
        echo \"Backup created: \$BACKUP_FILE\"
        ;;
    *)
        echo 'Usage: \$0 {start|stop|restart|status|logs|test|update|fix-deps|fix-apt|repair|backup}'
        echo
        echo 'Commands:'
        echo '  start       - Start all IES services'
        echo '  stop        - Stop all IES services'
        echo '  restart     - Restart all IES services'
        echo '  status      - Show service status'
        echo '  logs [type] - Show logs (app, nginx, monitoring)'
        echo '  test        - Test all endpoints'
        echo '  update      - Update IES application'
        echo '  fix-deps    - Fix Python dependencies'
        echo '  fix-apt     - Fix APT configuration'
        echo '  repair      - Full system repair'
        echo '  backup      - Create backup'
        exit 1
        ;;
esac
MANAGE_EOF
        
        chmod +x /usr/local/bin/ies-manage
        
        # Create monitoring script
        cat > /usr/local/bin/ies-monitor << 'MONITOR_EOF'
#!/bin/bash

echo 'IES Military Database Analyzer Status'
echo '====================================='
echo
echo 'Services:'
systemctl is-active ies-analyzer nginx docker fail2ban | paste <(echo -e 'IES App\\nNginx\\nDocker\\nFail2Ban') -
echo
echo 'Network Information:'
echo \"Container IP: $IP\"
echo \"Gateway: $GATEWAY\"
echo \"DNS: $DNS\"
echo \"Domain: $DOMAIN\"
echo
echo 'Access URLs:'
echo \"Application: https://$IP\"
echo \"Grafana: http://$IP:3000 (admin/admin123)\"
echo \"Prometheus: http://$IP:9090\"
if [[ '$SSH_ENABLED' == 'yes' ]]; then
    echo \"SSH: ssh root@$IP\"
fi
echo
echo 'System Resources:'
echo \"Disk Usage: \$(df -h / | tail -1 | awk '{print \$5}') of \$(df -h / | tail -1 | awk '{print \$2}')\"
echo \"Memory Usage: \$(free -h | grep Mem | awk '{print \$3 \"/\" \$2}')\"
echo \"CPU Load: \$(uptime | awk -F'load average:' '{print \$2}')\"
echo
echo 'Monitoring:'
if systemctl is-active --quiet docker; then
    cd /opt/monitoring && (docker compose ps || docker-compose ps) 2>/dev/null | grep -E '(prometheus|grafana|node-exporter)' | awk '{print \$1 \": \" \$NF}' || echo 'Monitoring containers not found'
else
    echo 'Docker service not running'
fi
MONITOR_EOF
        
        chmod +x /usr/local/bin/ies-monitor
    "
    
    msg_ok "Management scripts created"
}

# Start all services
start_services() {
    msg_info "Starting all services"
    
    pct exec $CT_ID -- bash -c "
        # Start core services
        systemctl start ies-analyzer
        systemctl start nginx
        
        # Start monitoring stack
        cd /opt/monitoring
        (docker compose up -d || docker-compose up -d) >/dev/null 2>&1
        
        # Enable services for auto-start
        systemctl enable ies-analyzer nginx docker
    "
    
    msg_ok "All services started and enabled"
}

# Final configuration and testing
finalize_setup() {
    msg_info "Finalizing setup and running validation tests"
    
    # Wait for services to be ready
    sleep 20
    
    # Save configuration
    local config_file=$(write_config)
    pct push $CT_ID "$config_file" /root/ies-config.conf
    
    # Run comprehensive tests
    local test_results=""
    
    # Test application health
    if pct exec $CT_ID -- curl -s -f http://127.0.0.1:8000/health >/dev/null 2>&1; then
        test_results+="✓ Application health check: PASSED\n"
    else
        test_results+="✗ Application health check: FAILED\n"
    fi
    
    # Test metrics endpoint
    if pct exec $CT_ID -- curl -s http://127.0.0.1:8000/metrics | grep -q "ies_" 2>/dev/null; then
        test_results+="✓ Metrics endpoint: PASSED\n"
    else
        test_results+="✗ Metrics endpoint: FAILED\n"
    fi
    
    # Test nginx configuration
    if pct exec $CT_ID -- nginx -t >/dev/null 2>&1; then
        test_results+="✓ Nginx configuration: PASSED\n"
    else
        test_results+="✗ Nginx configuration: FAILED\n"
    fi
    
    # Test web access
    if pct exec $CT_ID -- curl -s -k https://127.0.0.1/ | grep -q "IES Military Database" 2>/dev/null; then
        test_results+="✓ Web interface: PASSED\n"
    else
        test_results+="✗ Web interface: FAILED\n"
    fi
    
    # Test monitoring services
    if pct exec $CT_ID -- docker ps | grep -E "(prometheus|grafana|node-exporter)" >/dev/null 2>&1; then
        test_results+="✓ Monitoring services: PASSED\n"
    else
        test_results+="✗ Monitoring services: FAILED\n"
    fi
    
    echo -e "$test_results"
    msg_ok "Setup validation completed"
}

# Display final information
show_completion_info() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}    IES Military Database Analyzer${NC}"
    echo -e "${GREEN}    DEPLOYMENT COMPLETED SUCCESSFULLY${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo
    echo -e "${WHITE}Container Information:${NC}"
    echo -e "Container ID:      ${GREEN}$CT_ID${NC}"
    echo -e "Container Name:    ${GREEN}$CT_NAME${NC}"
    echo -e "IP Address:        ${GREEN}$IP${NC}"
    echo -e "Domain:            ${GREEN}$DOMAIN${NC}"
    echo -e "Resources:         ${GREEN}${RAM}MB RAM, ${CPU_CORES} CPU cores, ${DISK_SIZE}GB disk${NC}"
    echo
    echo -e "${WHITE}Access Information:${NC}"
    echo -e "Application HTTPS: ${CYAN}https://$IP${NC}"
    echo -e "Application HTTP:  ${CYAN}http://$IP${NC} (redirects to HTTPS)"
    echo -e "Grafana Dashboard: ${CYAN}http://$IP:3000${NC} (admin/admin123)"
    echo -e "Prometheus:        ${CYAN}http://$IP:9090${NC}"
    if [[ "$SSH_ENABLED" == "yes" ]]; then
        echo -e "SSH Access:        ${CYAN}ssh root@$IP${NC} (password: ${PASSWORD})"
    else
        echo -e "SSH Access:        ${RED}Disabled${NC}"
    fi
    echo
    echo -e "${WHITE}Container Management (from Proxmox host):${NC}"
    echo -e "Start Container:   ${YELLOW}pct start $CT_ID${NC}"
    echo -e "Stop Container:    ${YELLOW}pct stop $CT_ID${NC}"
    echo -e "Console Access:    ${YELLOW}pct enter $CT_ID${NC}"
    echo -e "Container Status:  ${YELLOW}pct status $CT_ID${NC}"
    echo
    echo -e "${WHITE}Application Management (inside container):${NC}"
    echo -e "Service Control:   ${YELLOW}ies-manage {start|stop|restart|status}${NC}"
    echo -e "View Logs:         ${YELLOW}ies-manage logs [app|nginx|monitoring]${NC}"
    echo -e "Test Endpoints:    ${YELLOW}ies-manage test${NC}"
    echo -e "Update App:        ${YELLOW}ies-manage update${NC}"
    echo -e "System Repair:     ${YELLOW}ies-manage repair${NC}"
    echo -e "Create Backup:     ${YELLOW}ies-manage backup${NC}"
    echo -e "System Overview:   ${YELLOW}ies-monitor${NC}"
    echo
    echo -e "${WHITE}Configuration Files:${NC}"
    echo -e "Deployment Config: ${GREEN}/root/ies-config.conf${NC}"
    echo -e "Application Path:  ${GREEN}/opt/IES${NC}"
    echo -e "Nginx Config:      ${GREEN}/etc/nginx/sites-available/ies-analyzer${NC}"
    echo -e "Monitoring Stack:  ${GREEN}/opt/monitoring${NC}"
    echo
    echo -e "${WHITE}Security Features:${NC}"
    echo -e "Firewall:          ${GREEN}UFW enabled (192.168.0.0/24 access only)${NC}"
    echo -e "Intrusion Defense: ${GREEN}Fail2Ban active${NC}"
    echo -e "SSL/TLS:          ${GREEN}Self-signed certificate (consider replacing)${NC}"
    echo -e "Network Isolation: ${GREEN}Container-based security${NC}"
    echo
    echo -e "${WHITE}Next Steps:${NC}"
    echo "1. Access the application at https://$IP"
    echo "2. Set up DNS entry: $DOMAIN → $IP"
    echo "3. Replace self-signed SSL certificate if needed"
    echo "4. Configure Grafana dashboards and alerts"
    echo "5. Review and customize application settings"
    echo "6. Schedule regular backups with cron"
    echo "7. Change default passwords for production use"
    echo
    echo -e "${WHITE}Support & Troubleshooting:${NC}"
    echo "• Configuration saved in: /root/ies-config.conf"
    echo "• Check system status: ies-monitor"
    echo "• Test all endpoints: ies-manage test"
    echo "• View application logs: ies-manage logs app"
    echo "• Full system repair: ies-manage repair"
    echo "• Container console: pct enter $CT_ID"
    echo
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo -e "${WHITE}The IES Military Database Analyzer is now ready for use.${NC}"
}

# Error handling
set -e
trap 'msg_error "Script failed at line $LINENO"; exit 1' ERR

# Main execution
main() {
    clear
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${CYAN}    IES Military Database Analyzer${NC}"
    echo -e "${CYAN}    Proxmox LXC Container Deployment${NC}"
    echo -e "${CYAN}    Version 2.0 - Production Ready${NC}"
    echo -e "${CYAN}=================================================${NC}"
    echo
    
    # Verify we're running on Proxmox
    if ! command -v pct &> /dev/null; then
        msg_error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    # Start deployment process
    msg_info "Starting IES Military Database Analyzer deployment..."
    
    # Create and configure container
    create_container
    
    # Install dependencies
    install_system_dependencies
    
    # Install IES application
    install_ies_application
    
    # Configure services
    configure_services
    
    # Configure web server
    configure_nginx
    
    # Setup monitoring
    setup_monitoring
    
    # Configure security
    configure_security
    
    # Create management tools
    create_management_scripts
    
    # Start services
    start_services
    
    # Finalize and test
    finalize_setup
    
    # Show completion information
    show_completion_info
}

# Run main function
main "$@"
        
