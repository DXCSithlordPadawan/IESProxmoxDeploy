# IES Military Database Analyzer - Complete Proxmox LXC Deployment

This repository provides two streamlined deployment solutions for the IES Military Database Analyzer on Proxmox VE, combining all fixes and features from multiple scripts into production-ready installers.

## 🚀 Quick Deployment Options

### Option 1: One-Line Quick Install (Recommended for Testing)
```bash
# Run directly from Proxmox host console
bash <(curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install.sh)

# With custom configuration
export CT_ID=352 && export IP=192.168.0.201 && bash <(curl -sSL https://...)
```

### Option 2: Full Interactive Install (Recommended for Production)
```bash
# Download and run with configuration menu
wget https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/ies-complete-deploy.sh
chmod +x ies-complete-deploy.sh
./ies-complete-deploy.sh
```

### Option 3: Non-Interactive with Custom Parameters
```bash
./ies-complete-deploy.sh \
  --ct-id 350 \
  --ip 192.168.0.199 \
  --domain ies-production.local \
  --password "SecurePassword123!" \
  --non-interactive
```

## 📋 Default Configuration

| Parameter | Default Value | Environment Override | Description |
|-----------|---------------|---------------------|-------------|
| **Container ID** | 351 | `CT_ID` | LXC container identifier |
| **IP Address** | 192.168.0.200 | `IP` | Static IP assignment |
| **Gateway** | 192.168.0.1 | `GATEWAY` | Network gateway |
| **DNS Server** | 192.168.0.110 | `DNS` | DNS resolver |
| **Storage** | local-lvm | `STORAGE` | Proxmox storage pool |
| **Root Password** | BobTheBigRedBus-0 | `PASSWORD` | Default password |
| **SSH Access** | Enabled | `SSH_ENABLED` | Remote access |
| **Domain** | ies-analyzer.local | `DOMAIN` | Application domain |
| **RAM** | 2048MB | `RAM` | Memory allocation |
| **CPU Cores** | 2 | `CPU_CORES` | vCPU cores |
| **Disk Size** | 8GB | `DISK_SIZE` | Root filesystem size |

## 🎯 What's Included

### ✅ All Major Fixes Implemented
- **APT Repository Issues**: Proper Docker repository configuration with fallback
- **Python Dependencies**: Sequential installation preventing conflicts
- **Application Arguments**: Support for `--host` and `--port` parameters
- **SSL Certificate**: Proper generation with SAN extensions
- **Service Management**: Enhanced systemd services with health checks
- **Network Connectivity**: Comprehensive testing and validation

### 🏗️ Complete Application Stack
- **IES Military Database Analyzer v3.0** - Enhanced with metrics support
- **Python 3.11 Virtual Environment** - Isolated dependencies
- **Flask Web Framework** - Modern responsive UI
- **Nginx Reverse Proxy** - SSL/TLS termination and security
- **Systemd Integration** - Proper service management

### 📊 Monitoring & Observability
- **Prometheus** (port 9090) - Metrics collection with 7-day retention
- **Grafana** (port 3000) - Visualization dashboards (admin/admin123)
- **Node Exporter** - System metrics
- **Application Metrics** - Custom IES performance monitoring
- **Health Checks** - Comprehensive endpoint testing

### 🔒 Security & Compliance
- **UFW Firewall** - Network access control (192.168.0.0/24 only)
- **Fail2Ban** - Intrusion prevention system
- **SSL/TLS Encryption** - All HTTP traffic redirected to HTTPS
- **Network Isolation** - Container-level security
- **Access Controls** - IP-based restrictions

### 🛠️ Management Tools
- **`ies-manage`** - Comprehensive service management utility
- **`ies-monitor`** - Real-time system status dashboard
- **`ies-emergency-repair`** - Automated problem resolution
- **Automated Backups** - Configuration and data protection

## 🌐 Access Information

After successful deployment, access your services:

| Service | URL | Credentials | Purpose |
|---------|-----|-------------|---------|
| **Main Application** | https://192.168.0.200 | None | Primary IES interface |
| **Grafana Dashboard** | http://192.168.0.200:3000 | admin/admin123 | Monitoring dashboards |
| **Prometheus** | http://192.168.0.200:9090 | None | Metrics and alerts |
| **SSH Access** | `ssh root@192.168.0.200` | BobTheBigRedBus-0 | Remote management |

## 🎛️ Management Commands

### Container Management (Proxmox Host)
```bash
# Basic operations
pct start 351               # Start container
pct stop 351                # Stop container
pct restart 351             # Restart container
pct enter 351               # Access container console
pct status 351              # Check container status

# Resource management
pct set 351 -memory 4096    # Increase RAM to 4GB
pct set 351 -cores 4        # Increase CPU cores
pct config 351              # View configuration

# Backup operations
vzdump 351 --storage local  # Create container backup
pct restore 351 /path/to/backup  # Restore from backup
```

### Application Management (Inside Container)
```bash
# Service operations
ies-manage start            # Start all IES services
ies-manage stop             # Stop all IES services
ies-manage restart          # Restart all services
ies-manage status           # Check service status

# Monitoring and diagnostics
ies-manage test             # Test all endpoints
ies-monitor                 # System status dashboard
ies-manage logs app         # Application logs
ies-manage logs nginx       # Web server logs
ies-manage logs monitoring  # Docker monitoring logs

# Maintenance operations
ies-manage update           # Update IES application
ies-manage backup           # Create system backup
ies-manage repair           # Full system repair
ies-manage fix-deps         # Fix Python dependencies only
ies-manage fix-apt          # Fix APT configuration only

# Emergency recovery
ies-emergency-repair        # Comprehensive automated repair
```

## 🔧 Troubleshooting Guide

### Common Issues and Solutions

#### Issue: Container Won't Start
```bash
# Check container logs
journalctl -u lxc@351

# Verify container configuration
pct config 351

# Check resource availability
pvesm status
```

#### Issue: Application Not Accessible
```bash
# Inside container, check services
ies-manage status
ies-manage test

# Check specific services
systemctl status ies-analyzer nginx

# Verify network connectivity
curl -I http://localhost:8000/health
```

#### Issue: Python Import Errors
```bash
# Fix dependencies automatically
ies-manage fix-deps

# Manual fix
cd /opt/IES
source ies_env/bin/activate
python3 -c "import networkx, pandas, flask"
```

#### Issue: APT Repository Errors
```bash
# Fix APT configuration
ies-manage fix-apt

# Verify fix
apt update
```

#### Issue: SSL Certificate Problems
```bash
# Regenerate certificates
ies-manage repair

# Manual certificate regeneration
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=192.168.0.200'
systemctl reload nginx
```

### Automated Problem Resolution

#### Emergency Repair Workflow
```bash
# Inside container - comprehensive repair
ies-emergency-repair

# This automatically:
# 1. Fixes APT configuration issues
# 2. Reinstalls Python dependencies
# 3. Updates application compatibility
# 4. Restarts all services
# 5. Tests system functionality
```

#### Health Check Workflow
```bash
# Quick system health check
ies-manage test

# Expected output:
# Health: 200
# HTTP: 200  
# HTTPS: 200

# Detailed status check
ies-monitor

# Shows:
# - Service status
# - Resource usage
# - Network connectivity
# - Quick health test
```

## 📊 Monitoring and Dashboards

### Grafana Dashboards
Access at `http://your-ip:3000` (admin/admin123):

1. **Application Performance**
   - HTTP request rates and response times
   - Error rates and status codes
   - Database query performance
   - Custom application metrics

2. **System Resources**
   - CPU, memory, and disk utilization
   - Network traffic patterns
   - Container resource usage
   - Service health indicators

3. **Security Monitoring**
   - Failed authentication attempts
   - Firewall blocks and intrusion attempts
   - SSL certificate status
   - Access pattern analysis

### Prometheus Metrics
Available at `http://your-ip:9090`:

```
# Application-specific metrics
ies_http_requests_total         # Request counter by method/endpoint/status
ies_http_request_duration_seconds  # Response time histogram
ies_system_cpu_percent          # CPU usage gauge
ies_system_memory_bytes         # Memory usage gauge
ies_application_status          # Application health status

# System metrics (via Node Exporter)
node_cpu_seconds_total          # CPU time counters
node_memory_MemTotal_bytes      # Total memory
node_filesystem_size_bytes      # Disk space
node_network_receive_bytes_total # Network traffic
```

## 🔒 Security Configuration

### Network Security
```bash
# Default firewall rules (applied automatically)
ufw allow from 192.168.0.0/24 to any port 22    # SSH
ufw allow from 192.168.0.0/24 to any port 80    # HTTP
ufw allow from 192.168.0.0/24 to any port 443   # HTTPS
ufw allow from 192.168.0.0/24 to any port 3000  # Grafana
ufw allow from 192.168.0.0/24 to any port 9090  # Prometheus
```

### SSL/TLS Configuration
- Self-signed certificates generated automatically
- All HTTP traffic redirected to HTTPS
- Modern TLS protocols (1.2, 1.3) with secure ciphers
- Security headers (HSTS, X-Frame-Options, etc.)

### Access Controls
- Nginx IP-based restrictions
- Application-level authentication hooks
- Fail2Ban intrusion prevention
- Container isolation and privilege separation

### Security Hardening Recommendations
```bash
# 1. Change default passwords (critical)
passwd root
# Edit Grafana admin password in docker-compose.yml

# 2. Replace self-signed certificates
cp your-cert.crt /etc/nginx/ssl/server.crt
cp your-cert.key /etc/nginx/ssl/server.key
systemctl reload nginx

# 3. Configure SSH key authentication
mkdir -p ~/.ssh
# Add public key to ~/.ssh/authorized_keys
# Disable password auth in /etc/ssh/sshd_config

# 4. Set up centralized logging
# Configure rsyslog or similar

# 5. Enable automatic security updates
apt-get install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

## 🔄 Maintenance and Updates

### Regular Maintenance Schedule

#### Daily (Automated)
- Health check monitoring
- Log rotation
- Basic security monitoring

#### Weekly (Manual)
```bash
# Inside container
ies-manage status          # Check service health
ies-manage test           # Verify endpoints
ies-monitor               # Review system status
```

#### Monthly (Manual)
```bash
# System updates
apt-get update && apt-get upgrade -y

# Application updates
ies-manage update

# Backup verification
ies-manage backup
```

#### Quarterly (Manual)
```bash
# Comprehensive maintenance
ies-manage repair         # Full system repair
ies-emergency-repair      # Emergency fixes if needed

# SSL certificate renewal (if needed)
# Performance optimization review
# Security audit and updates
```

### Update Procedures

#### Application Updates
```bash
# Automatic update
ies-manage update

# Manual update process
cd /opt/IES
git pull origin main
source ies_env/bin/activate
pip install --upgrade -r requirements.txt
systemctl restart ies-analyzer
```

#### System Updates
```bash
# Standard system updates
apt-get update
apt-get upgrade -y
apt-get autoremove -y

# Update monitoring stack
cd /opt/monitoring
docker compose pull
docker compose up -d
```

## 💾 Backup and Recovery

### Automated Backup Creation
```bash
# Create application backup
ies-manage backup

# Scheduled backups (add to crontab)
echo "0 2 * * * /usr/local/bin/ies-manage backup" | crontab -
```

### Container-Level Backup
```bash
# From Proxmox host - full container backup
vzdump 351 --storage local --compress gzip

# Restore from container backup
pct restore 351 /var/lib/vz/dump/vzdump-lxc-351-*.tar.gz
```

### Data Export and Migration
```bash
# Export application data
cd /opt/IES
tar -czf /tmp/ies-data-$(date +%Y%m%d).tar.gz data/ config/ logs/

# Copy to external storage
scp /tmp/ies-data-*.tar.gz user@backup-server:/backups/

# Import to new container
scp backup-server:/backups/ies-data-*.tar.gz /tmp/
cd /opt/IES
tar -xzf /tmp/ies-data-*.tar.gz
```

## 🚀 Advanced Deployment Scenarios

### High Availability Setup
```bash
# Deploy multiple containers for load balancing
for i in {351..353}; do
  CT_ID=$i IP=192.168.0.$((200+$i-351)) ./ies-complete-deploy.sh --non-interactive
done

# Configure external load balancer (HAProxy/Nginx)
# Point to containers: 192.168.0.200, 192.168.0.201, 192.168.0.202
```

### Development Environment
```bash
# Development setup with debugging
CT_ID=399 IP=192.168.0.199 DOMAIN=ies-dev.local ./ies-complete-deploy.sh
pct enter 399
ies-manage logs app  # Monitor development logs
```

### Production Environment
```bash
# Enhanced production deployment
./ies-complete-deploy.sh \
  --ct-id 300 \
  --ip 192.168.0.100 \
  --domain ies-production.company.com \
  --storage "ssd-storage" \
  --password "$(openssl rand -base64 32)" \
  --non-interactive

# Additional production hardening required post-installation
```

### Multi-Environment Management
```bash
# Environment variable approach for multiple deployments
export ENVIRONMENTS=(dev staging prod)
export BASE_CT_ID=350
export BASE_IP=192.168.0.199

for i in "${!ENVIRONMENTS[@]}"; do
  env=${ENVIRONMENTS[$i]}
  CT_ID=$((BASE_CT_ID + i)) \
  IP=$((BASE_IP + i)) \
  DOMAIN="ies-${env}.local" \
  ./ies-complete-deploy.sh --non-interactive
done
```

## 📈 Performance Optimization

### Resource Scaling
```bash
# From Proxmox host - adjust based on workload
pct set 351 -memory 2048    # Light usage (default)
pct set 351 -memory 4096    # Moderate usage
pct set 351 -memory 8192    # Heavy usage
pct set 351 -cores 2        # Light usage (default)
pct set 351 -cores 4        # Heavy processing
pct set 351 -cores 8        # High-performance requirements
```

### Application Optimization
```bash
# Inside container - optimize for performance
cd /opt/IES
source ies_env/bin/activate

# Install performance packages
pip install gunicorn[gevent] uvloop

# Update service for production WSGI
# Edit /etc/systemd/system/ies-analyzer.service
# Change ExecStart to use gunicorn with workers
```

### Database Optimization
```bash
# If using external database
nano /opt/IES/config/database.conf

# Connection pooling settings
DATABASE_POOL_SIZE=20
DATABASE_MAX_CONNECTIONS=100
DATABASE_TIMEOUT=30
```

### Monitoring Optimization
```bash
# Adjust retention policies based on usage
nano /opt/monitoring/prometheus/prometheus.yml

# For high-volume environments
storage.tsdb.retention.time=3d

# For archival environments
storage.tsdb.retention.time=30d
```

## 🔍 Detailed Component Information

### Application Architecture
```
IES Container Architecture:
├── /opt/IES/                          # Main application
│   ├── military_database_analyzer_v3.py  # Enhanced main application
│   ├── ies_env/                       # Python virtual environment
│   ├── data/                          # Application data storage
│   ├── config/                        # Configuration files
│   ├── logs/                          # Application logs
│   └── static/templates/              # Web assets
├── /etc/nginx/                        # Web server configuration
│   ├── sites-available/ies-analyzer  # Main site configuration
│   └── ssl/                           # SSL certificates
├── /opt/monitoring/                   # Monitoring stack
│   ├── docker-compose.yml            # Monitoring services
│   ├── prometheus/                    # Metrics collection
│   └── grafana/                       # Dashboards
└── /usr/local/bin/                    # Management utilities
    ├── ies-manage                     # Main management script
    ├── ies-monitor                    # Status dashboard
    └── ies-emergency-repair           # Automated repair
```

### Network Architecture
```
Network Flow:
Internet/LAN → Proxmox Host → Container Bridge → IES Container
                                                      ↓
Client HTTPS:443 → Nginx → Flask:8000 → IES Application
Client HTTP:3000 → Grafana Dashboard
Client HTTP:9090 → Prometheus Metrics
```

### Service Dependencies
```
Service Startup Order:
1. Docker Engine
2. IES Application (Flask)
3. Nginx (Reverse Proxy)
4. Monitoring Stack (Prometheus/Grafana)
5. Security Services (UFW/Fail2Ban)
```

## 📚 API and Integration

### Health Check API
```bash
# Application health endpoint
curl -X GET http://192.168.0.200:8000/health

# Response format:
{
  "status": "healthy",
  "timestamp": 1703097600.123,
  "version": "3.0",
  "uptime_seconds": 3600,
  "python_version": "3.11.0",
  "dependencies_ok": true
}
```

### Metrics API
```bash
# Prometheus metrics endpoint
curl -X GET http://192.168.0.200:8000/metrics

# Sample metrics output:
# TYPE ies_http_requests_total counter
ies_http_requests_total{method="GET",endpoint="home",status="200"} 42
# TYPE ies_system_cpu_percent gauge
ies_system_cpu_percent 15.2
# TYPE ies_application_status gauge
ies_application_status 1
```

### Configuration API
```bash
# Runtime configuration (if implemented)
curl -X GET http://192.168.0.200:8000/config
curl -X POST http://192.168.0.200:8000/config -d '{"setting":"value"}'
```

## 🔗 Integration Examples

### External Monitoring Integration
```bash
# Integrate with external Prometheus
# Add to external prometheus.yml:
scrape_configs:
  - job_name: 'ies-production'
    static_configs:
      - targets: ['192.168.0.200:8000']
    scrape_interval: 30s
    metrics_path: /metrics
```

### Log Aggregation
```bash
# Configure rsyslog for centralized logging
echo '*.* @log-server:514' >> /etc/rsyslog.conf

# Or configure container to send logs to host
# From Proxmox host:
pct set 351 -features nesting=1,mount=nfs
```

### Backup Integration
```bash
# Integration with backup systems
cat > /etc/cron.d/ies-backup << EOF
0 2 * * * root /usr/local/bin/ies-manage backup
0 3 * * 0 root vzdump 351 --storage backup-nfs --compress gzip
EOF
```

## 🆘 Emergency Procedures

### Complete System Recovery
```bash
# If container is completely unresponsive
pct stop 351
pct start 351
sleep 30
pct enter 351
ies-emergency-repair
```

### Disaster Recovery Checklist
1. **Immediate Response**
   - Stop affected container: `pct stop 351`
   - Check Proxmox host resources: `pvesm status`
   - Review container logs: `journalctl -u lxc@351`

2. **Service Recovery**
   - Start container: `pct start 351`
   - Run emergency repair: `ies-emergency-repair`
   - Test all endpoints: `ies-manage test`

3. **Data Recovery**
   - Restore from latest backup if needed
   - Verify data integrity
   - Resume normal operations

### Rollback Procedures
```bash
# If update causes issues, rollback steps:
cd /opt/IES
git log --oneline -10  # Find previous commit
git reset --hard <previous-commit-hash>
source ies_env/bin/activate
pip install -r requirements.txt
systemctl restart ies-analyzer
ies-manage test
```

## 📞 Support and Community

### Self-Service Troubleshooting
1. **Check Status**: `ies-monitor` - Quick system overview
2. **Test Connectivity**: `ies-manage test` - Verify all endpoints
3. **Review Logs**: `ies-manage logs app` - Check application logs
4. **Run Repair**: `ies-manage repair` - Automated problem resolution
5. **Emergency Fix**: `ies-emergency-repair` - Comprehensive repair

### Log Analysis
```bash
# Application logs
journalctl -u ies-analyzer -f

# System logs  
journalctl -xe

# Nginx logs
tail -f /var/log/nginx/error.log
tail -f /var/log/nginx/access.log

# Container logs (from Proxmox host)
journalctl -u lxc@351
```

### Performance Analysis
```bash
# System resource usage
htop
iotop
iftop

# Application performance
curl -w "@curl-format.txt" -s -o /dev/null https://192.168.0.200

# Database performance (if applicable)
# Use application-specific monitoring tools
```

### Documentation Locations
- **Installation Info**: `/root/ies-deployment-info.txt` (inside container)
- **Configuration Files**: `/opt/IES/config/`
- **Log Files**: `/opt/IES/logs/` and `/var/log/`
- **Management Scripts**: `/usr/local/bin/ies-*`

## ✅ Deployment Validation Checklist

### Pre-Installation
- [ ] Proxmox VE environment verified (`pct` command available)
- [ ] Container ID available (check with `pct status <id>`)
- [ ] Network configuration confirmed
- [ ] Storage pool accessible
- [ ] Ubuntu template available or will be downloaded

### Post-Installation Validation
```bash
# Run comprehensive test suite
ies-manage test

# Expected results:
# Health: 200 ✓
# HTTP: 200 ✓  
# HTTPS: 200 ✓

# Service status verification
ies-manage status

# Expected services active:
# IES App: active
# Nginx: active  
# Docker: active

# Network connectivity test
ies-monitor

# Expected output:
# IP: 192.168.0.200
# Services: active active active
# App: ✓ Healthy
```

### Security Validation
```bash
# Firewall status
ufw status verbose

# SSL certificate verification
openssl x509 -in /etc/nginx/ssl/server.crt -text -noout

# Service isolation check
systemctl status ies-analyzer nginx docker fail2ban
```

### Performance Validation
```bash
# Load test (basic)
for i in {1..10}; do 
  curl -s -o /dev/null -w "%{http_code} %{time_total}\n" https://192.168.0.200
done

# Memory usage check
free -h

# Disk usage check  
df -h
```

This comprehensive deployment solution provides a production-ready IES Military Database Analyzer installation with automated problem resolution, extensive monitoring, robust security, and comprehensive management capabilities. The combined scripts resolve all known deployment issues while providing both quick installation and full configuration control options.