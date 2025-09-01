#!/usr/bin/env bash

# IES Military Database Analyzer LXC Container Creation Script
# Compatible with Proxmox Community Scripts format
# Version: 1.0.0
# Author: DXC Technology
# Description: Creates an LXC container with IES Military Database Analyzer

source /dev/stdin <<< "$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

msg_info "Starting IES Military Database Analyzer LXC Container Setup"

# Default configuration
DEFAULT_CT_ID="351"
DEFAULT_CT_NAME="ies-analyzer"
DEFAULT_DISK_SIZE="8"
DEFAULT_RAM="2048"
DEFAULT_CPU_CORES="2"
DEFAULT_IP="192.168.0.200"
DEFAULT_GATEWAY="192.168.0.1"
DEFAULT_DNS="192.168.0.110"
DEFAULT_STORAGE="pve1"
DEFAULT_PASSWORD="BobTheBigRedBus-0"
DEFAULT_SSH_ENABLED="yes"
DEFAULT_CERT_SERVER="192.168.0.122"
DEFAULT_DOMAIN="ies-analyzer.local"
DEFAULT_TIMEZONE="America/New_York"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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
                show_config_menu
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

# Parse command line arguments for non-interactive mode
while [[ $# -gt 0 ]]; do
    case $1 in
        --ct-id)
            CT_ID="$2"
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
        --non-interactive)
            NON_INTERACTIVE="yes"
            shift
            ;;
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
    
    # Create the container
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
        --start 1
    
    if [[ $? -eq 0 ]]; then
        msg_ok "Container $CT_ID created successfully"
    else
        msg_error "Failed to create container"
        exit 1
    fi
    
    # Wait for container to start
    msg_info "Waiting for container to start..."
    sleep 10
    
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

# Install system dependencies
install_system_dependencies() {
    msg_info "Installing system dependencies"
    
    pct exec $CT_ID -- bash -c "
        apt-get update
        apt-get upgrade -y
        apt-get install -y \
            curl \
            wget \
            git \
            python3 \
            python3-pip \
            python3-venv \
            nginx \
            supervisor \
            ufw \
            fail2ban \
            htop \
            nano \
            vim \
            unzip \
            ca-certificates \
            gnupg \
            lsb-release \
            software-properties-common
    "
    
    if [[ "$SSH_ENABLED" == "yes" ]]; then
        pct exec $CT_ID -- bash -c "
            apt-get install -y openssh-server
            systemctl enable ssh
            systemctl start ssh
        "
        msg_ok "SSH service installed and enabled"
    fi
    
    msg_ok "System dependencies installed"
}

# Install Docker (for monitoring stack)
install_docker() {
    msg_info "Installing Docker"
    
    pct exec $CT_ID -- bash -c "
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo 'deb [arch=\$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable' | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        systemctl enable docker
        systemctl start docker
        usermod -aG docker root
    "
    
    msg_ok "Docker installed successfully"
}

# Install IES Application
install_ies_application() {
    msg_info "Installing IES Military Database Analyzer"
    
    pct exec $CT_ID -- bash -c "
        cd /opt
        git clone https://github.com/DXCSithlordPadawan/IES.git
        cd IES
        
        # Create virtual environment
        python3 -m venv ies_env
        source ies_env/bin/activate
        
        # Install Python dependencies with explicit package list
        pip install --upgrade pip
        
        # Install core dependencies first
        pip install flask pandas numpy matplotlib seaborn plotly networkx \\
                   scikit-learn jinja2 gunicorn prometheus-client psutil
        
        # Try requirements.txt if it exists (but don't fail if missing packages)
        if [ -f requirements.txt ]; then
            pip install -r requirements.txt || true
        fi
        
        # Verify critical dependencies are installed
        python3 -c 'import networkx, plotly, pandas, flask, matplotlib, seaborn, numpy' || {
            echo 'Installing missing dependencies...'
            pip install --force-reinstall networkx plotly pandas flask matplotlib seaborn numpy scikit-learn
        }
        
        # Create application directories
        mkdir -p /opt/IES/{logs,data,config,static,templates}
        chmod 755 /opt/IES/{logs,data,config}
        
        # Create systemd service
        cat > /etc/systemd/system/ies-analyzer.service << 'SERVICE_EOF'
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
SERVICE_EOF
        
        # Test the application before enabling service
        source ies_env/bin/activate
        python3 -c 'import sys; sys.path.append(\"/opt/IES\"); from military_database_analyzer_v3 import MilitaryDatabaseAnalyzer; print(\"Import test successful\")' || {
            echo 'Application import test failed, installing additional dependencies...'
            pip install --upgrade flask pandas numpy matplotlib seaborn plotly networkx scikit-learn jinja2
        }
        
        systemctl daemon-reload
        systemctl enable ies-analyzer
        systemctl start ies-analyzer
    "
    
    msg_ok "IES Application installed and started"
}

# Add troubleshooting function
troubleshoot_installation() {
    msg_info "Running post-installation diagnostics..."
    
    # Check Python environment
    pct exec $CT_ID -- bash -c "
        cd /opt/IES
        source ies_env/bin/activate
        echo 'Python version:' && python3 --version
        echo 'Pip version:' && pip --version
        echo 'Installed packages:'
        pip list | grep -E '(networkx|pandas|flask|matplotlib|plotly|seaborn|numpy|scikit-learn)'
    "
    
    # Test application imports
    pct exec $CT_ID -- bash -c "
        cd /opt/IES
        source ies_env/bin/activate
        echo 'Testing critical imports...'
        python3 -c 'import networkx; print(f\"networkx version: {networkx.__version__}\")' || echo 'networkx FAILED'
        python3 -c 'import pandas; print(f\"pandas version: {pandas.__version__}\")' || echo 'pandas FAILED'
        python3 -c 'import flask; print(f\"flask version: {flask.__version__}\")' || echo 'flask FAILED'
        python3 -c 'import matplotlib; print(f\"matplotlib version: {matplotlib.__version__}\")' || echo 'matplotlib FAILED'
        python3 -c 'import plotly; print(f\"plotly version: {plotly.__version__}\")' || echo 'plotly FAILED'
    "
    
    # Test main application import
    pct exec $CT_ID -- bash -c "
        cd /opt/IES
        source ies_env/bin/activate
        echo 'Testing main application import...'
        python3 -c 'from military_database_analyzer_v3 import MilitaryDatabaseAnalyzer; print(\"Main application import successful\")' || {
            echo 'Main application import FAILED'
            return 1
        }
    "
}

# Configure Nginx reverse proxy
configure_nginx() {
    msg_info "Configuring Nginx reverse proxy"
    
    pct exec $CT_ID -- bash -c "
        # Remove default nginx site
        rm -f /etc/nginx/sites-enabled/default
        
        # Create IES site configuration
        cat > /etc/nginx/sites-available/ies-analyzer << 'NGINX_EOF'
server {
    listen 80;
    server_name $DOMAIN _;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN _;
    
    # SSL Configuration (self-signed for now)
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!aNULL:!MD5:!DSS;
    ssl_prefer_server_ciphers on;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection \"1; mode=block\";
    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";
    
    # Application proxy
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        
        # Allow access from 192.168.0.0/24 network
        allow 192.168.0.0/24;
        allow 127.0.0.1;
        deny all;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        access_log off;
    }
    
    # Monitoring endpoints
    location /metrics {
        proxy_pass http://127.0.0.1:8000/metrics;
        allow 192.168.0.0/24;
        allow 127.0.0.1;
        deny all;
    }
}
NGINX_EOF
        
        # Create SSL directory and generate self-signed certificate
        mkdir -p /etc/nginx/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/server.key \
            -out /etc/nginx/ssl/server.crt \
            -subj '/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN'
        
        # Enable the site
        ln -sf /etc/nginx/sites-available/ies-analyzer /etc/nginx/sites-enabled/
        
        # Test and reload nginx
        nginx -t && systemctl reload nginx
    "
    
    msg_ok "Nginx configured successfully"
}

# Setup monitoring stack
setup_monitoring() {
    msg_info "Setting up monitoring stack with Docker Compose"
    
    pct exec $CT_ID -- bash -c "
        mkdir -p /opt/monitoring/{prometheus,grafana,config}
        cd /opt/monitoring
        
        # Create Prometheus configuration
        cat > prometheus/prometheus.yml << 'PROM_EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'ies-application'
    static_configs:
      - targets: ['$IP:8000']
    scrape_interval: 10s
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
      - '--storage.tsdb.retention.time=30d'
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
        docker compose up -d
    "
    
    msg_ok "Monitoring stack deployed"
}

# Configure firewall
configure_firewall() {
    msg_info "Configuring firewall"
    
    pct exec $CT_ID -- bash -c "
        # Configure UFW
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        
        # Allow SSH (if enabled)
        if [[ '$SSH_ENABLED' == 'yes' ]]; then
            ufw allow from 192.168.0.0/24 to any port 22
        fi
        
        # Allow HTTP/HTTPS from local network
        ufw allow from 192.168.0.0/24 to any port 80
        ufw allow from 192.168.0.0/24 to any port 443
        
        # Allow monitoring ports from local network
        ufw allow from 192.168.0.0/24 to any port 3000
        ufw allow from 192.168.0.0/24 to any port 9090
        
        ufw --force enable
        
        # Configure fail2ban
        systemctl enable fail2ban
        systemctl start fail2ban
    "
    
    msg_ok "Firewall configured"
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
        echo 'Application Status:'
        systemctl status ies-analyzer --no-pager
        echo
        echo 'Nginx Status:'
        systemctl status nginx --no-pager
        echo
        echo 'Monitoring Status:'
        cd /opt/monitoring && docker compose ps
        ;;
    logs)
        if [ -n \"\$2\" ]; then
            case \"\$2\" in
                app) journalctl -u ies-analyzer -f ;;
                nginx) journalctl -u nginx -f ;;
                monitoring) cd /opt/monitoring && docker compose logs -f ;;
                *) echo 'Available logs: app, nginx, monitoring' ;;
            esac
        else
            journalctl -u ies-analyzer --no-pager -n 50
        fi
        ;;
    update)
        echo 'Updating IES application...'
        cd /opt/IES
        git pull
        source ies_env/bin/activate
        pip install --upgrade -r requirements.txt 2>/dev/null || echo 'Requirements file not found'
        systemctl restart ies-analyzer
        echo 'Update complete'
        ;;
    backup)
        echo 'Creating backup...'
        tar -czf /opt/ies-backup-\$(date +%Y%m%d-%H%M%S).tar.gz \
            /opt/IES/data /opt/IES/config /opt/monitoring
        echo 'Backup created in /opt/'
        ;;
    *)
        echo 'Usage: \$0 {start|stop|restart|status|logs|update|backup}'
        echo
        echo 'Commands:'
        echo '  start    - Start all IES services'
        echo '  stop     - Stop all IES services' 
        echo '  restart  - Restart all IES services'
        echo '  status   - Show service status'
        echo '  logs     - Show logs (add: app, nginx, monitoring)'
        echo '  update   - Update IES application'
        echo '  backup   - Create backup'
        exit 1
        ;;
esac
MANAGE_EOF
        
        chmod +x /usr/local/bin/ies-manage
        
        # Create service monitoring script
        cat > /usr/local/bin/ies-monitor << 'MONITOR_EOF'
#!/bin/bash

# Simple monitoring script
echo 'IES Military Database Analyzer Status'
echo '====================================='
echo
echo 'Services:'
systemctl is-active ies-analyzer nginx docker | paste <(echo -e 'IES App\nNginx\nDocker') -
echo
echo 'Network:'
echo \"IP Address: $IP\"
echo \"Gateway: $GATEWAY\"
echo \"DNS: $DNS\"
echo
echo 'URLs:'
echo \"HTTP: http://$IP\"
echo \"HTTPS: https://$IP\"
echo \"Grafana: http://$IP:3000\"
echo \"Prometheus: http://$IP:9090\"
echo
echo 'Disk Usage:'
df -h / | tail -1
echo
echo 'Memory Usage:'
free -h | grep Mem
MONITOR_EOF
        
        chmod +x /usr/local/bin/ies-monitor
    "
    
    msg_ok "Management scripts created"
}

# Final configuration and testing
finalize_setup() {
    msg_info "Finalizing setup and running tests"
    
    # Wait for services to be ready
    sleep 15
    
    # Test application endpoint
    if pct exec $CT_ID -- curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/health | grep -q "200"; then
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
    
    # Save final configuration
    local config_file=$(write_config)
    pct push $CT_ID "$config_file" /root/ies-config.conf
    
    msg_ok "Setup completed successfully!"
}

# Display final information
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
    echo -e "Application HTTP:  ${CYAN}http://$IP${NC}"
    echo -e "Application HTTPS: ${CYAN}https://$IP${NC}"
    echo -e "Grafana Dashboard: ${CYAN}http://$IP:3000${NC} (admin/admin123)"
    echo -e "Prometheus:        ${CYAN}http://$IP:9090${NC}"
    echo
    echo -e "${BLUE}Container Management:${NC}"
    echo -e "Start Container:   ${YELLOW}pct start $CT_ID${NC}"
    echo -e "Stop Container:    ${YELLOW}pct stop $CT_ID${NC}"
    echo -e "Console Access:    ${YELLOW}pct enter $CT_ID${NC}"
    echo
    echo -e "${BLUE}Application Management (inside container):${NC}"
    echo -e "Service Control:   ${YELLOW}ies-manage {start|stop|restart|status}${NC}"
    echo -e "View Logs:         ${YELLOW}ies-manage logs [app|nginx|monitoring]${NC}"
    echo -e "Update App:        ${YELLOW}ies-manage update${NC}"
    echo -e "Create Backup:     ${YELLOW}ies-manage backup${NC}"
    echo -e "System Status:     ${YELLOW}ies-monitor${NC}"
    echo
    echo -e "${BLUE}Configuration:${NC}"
    echo -e "Config File:       ${GREEN}/root/ies-config.conf${NC}"
    echo -e "Application Path:  ${GREEN}/opt/IES${NC}"
    echo -e "Nginx Config:      ${GREEN}/etc/nginx/sites-available/ies-analyzer${NC}"
    echo -e "Monitoring:        ${GREEN}/opt/monitoring${NC}"
    echo
    echo -e "${BLUE}Security:${NC}"
    echo -e "Firewall:          ${GREEN}UFW enabled (192.168.0.0/24 only)${NC}"
    echo -e "Fail2Ban:          ${GREEN}Active${NC}"
    echo -e "SSL Certificate:   ${GREEN}Self-signed (consider replacing)${NC}"
    
    if [[ "$SSH_ENABLED" == "yes" ]]; then
        echo -e "SSH Access:        ${GREEN}Enabled${NC}"
        echo -e "SSH Command:       ${YELLOW}ssh root@$IP${NC}"
    else
        echo -e "SSH Access:        ${RED}Disabled${NC}"
    fi
    
    echo
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Access the application at https://$IP"
    echo "2. Configure proper SSL certificates if needed"
    echo "3. Set up DNS entries for $DOMAIN"
    echo "4. Review and customize application settings"
    echo "5. Configure monitoring alerts in Grafana"
    echo "6. Schedule regular backups"
    echo
    echo -e "${BLUE}Support:${NC}"
    echo "Configuration saved in container: /root/ies-config.conf"
    echo "For troubleshooting, access container: pct enter $CT_ID"
    echo "Check application logs: ies-manage logs app"
    echo
    echo -e "${GREEN}Deployment completed successfully!${NC}"
}

# Main execution
main() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  IES Military Database Analyzer       ${NC}"
    echo -e "${CYAN}  Proxmox LXC Container Deployment     ${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo
    
    # Verify we're running on Proxmox
    if ! command -v pct &> /dev/null; then
        msg_error "This script must be run on a Proxmox VE host"
        exit 1
    fi
    
    # Check for required template
    if [[ ! -f "/var/lib/vz/template/cache/ubuntu-22.04-standard_22.04-1_amd64.tar.zst" ]]; then
        msg_warn "Ubuntu 22.04 LXC template not found"
        msg_info "Downloading Ubuntu 22.04 template..."
        pveam update
        pveam download local ubuntu-22.04-standard_22.04-1_amd64.tar.zst
    fi
    
    # Start deployment process
    msg_info "Starting IES Military Database Analyzer deployment..."
    
    # Create container
    create_container
    
    # Install system dependencies
    install_system_dependencies
    
    # Install Docker for monitoring
    install_docker
    
    # Install IES application
    install_ies_application
    
    # Run diagnostics
    troubleshoot_installation
    
    # Configure Nginx
    configure_nginx
    
    # Setup monitoring
    setup_monitoring
    
    # Configure firewall
    configure_firewall
    
    # Create management scripts
    create_management_scripts
    
    # Finalize setup
    finalize_setup
    
    # Show completion information
    show_completion_info
}

# Run main function
main "$@"