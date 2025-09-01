# IES Military Database Analyzer - Proxmox LXC Deployment

This repository contains scripts to deploy the IES Military Database Analyzer as an LXC container on Proxmox VE, following the Proxmox Community Scripts format and conventions.

## 🚀 Quick Start

### One-Line Installation (Recommended)
```bash
# Run directly from Proxmox host console
bash <(curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install.sh)
```

### Custom Installation
```bash
# Download and run with custom settings
wget https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/deploy-ies-lxc.sh
chmod +x deploy-ies-lxc.sh
./deploy-ies-lxc.sh
```

## 📋 Default Configuration

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| **Container ID** | 351 | LXC container identifier |
| **IP Address** | 192.168.0.200 | Static IP assignment |
| **Gateway** | 192.168.0.1 | Network gateway |
| **DNS Server** | 192.168.0.110 | DNS resolver |
| **Storage** | pve1 | Proxmox storage pool |
| **Root Password** | BobTheBigRedBus-0 | Default password |
| **SSH Access** | Enabled | Remote access |
| **Cert Server** | 192.168.0.122 | Internal CA server |
| **Domain** | ies-analyzer.local | Application domain |

## 🎯 Features

### Core Application
- **IES Military Database Analyzer v3** - Full application stack
- **Python 3.11 Runtime** - Modern Python environment  
- **Flask Web Framework** - Robust web interface
- **Systemd Integration** - Proper service management
- **Virtual Environment** - Isolated Python dependencies

### Web Infrastructure
- **Nginx Reverse Proxy** - High-performance web server
- **SSL/TLS Termination** - Encrypted communications
- **Security Headers** - Modern web security
- **Access Controls** - Network-based restrictions
- **HTTP/HTTPS Redirection** - Automatic SSL enforcement

### Monitoring & Observability
- **Prometheus** (port 9090) - Metrics collection and alerting
- **Grafana** (port 3000) - Visualization dashboards
- **Node Exporter** - System metrics
- **Application Metrics** - Performance monitoring
- **Health Checks** - Service availability monitoring

### Security & Compliance
- **UFW Firewall** - Network access control
- **Fail2Ban** - Intrusion prevention
- **SSL/TLS Encryption** - Data protection
- **Network Isolation** - Container security
- **Access Logging** - Audit trails

## 🔧 Installation Methods

### Method 1: Interactive Installation
```bash
# Full configuration menu with options
./deploy-ies-lxc.sh
```

### Method 2: Non-Interactive Installation
```bash
# Use defaults, no prompts
./deploy-ies-lxc.sh --non-interactive
```

### Method 3: Custom Parameters
```bash
# Override specific settings
./deploy-ies-lxc.sh \
  --ct-id 352 \
  --ip 192.168.0.201 \
  --domain ies-prod.local \
  --password "SecurePass123!" \
  --non-interactive
```

### Method 4: Environment Variables
```bash
# Set environment variables before running
export CT_ID=353
export IP=192.168.0.202
export PASSWORD="MySecurePassword"
./quick-install.sh
```

## 🌐 Access Information

After successful deployment:

| Service | URL | Credentials |
|---------|-----|-------------|
| **Main Application** | https://192.168.0.200 | N/A |
| **Grafana Dashboard** | http://192.168.0.200:3000 | admin/admin123 |
| **Prometheus** | http://192.168.0.200:9090 | N/A |
| **SSH Access** | ssh root@192.168.0.200 | BobTheBigRedBus-0 |

## 🎛️ Management

### Container Management (Proxmox Host)
```bash
# Basic container operations
pct start 351        # Start container
pct stop 351         # Stop container  
pct restart 351      # Restart container
pct enter 351        # Access container console
pct status 351       # Check container status

# Container configuration
pct config 351       # View configuration
pct set 351 -memory 4096  # Increase RAM to 4GB
pct set 351 -cores 4      # Increase to 4 CPU cores
```

### Application Management (Inside Container)
```bash
# Service operations
ies-manage start      # Start all IES services
ies-manage stop       # Stop all IES services
ies-manage restart    # Restart all services
ies-manage status     # Check service status

# Monitoring and logs
ies-manage logs app   # Application logs
ies-manage logs nginx # Web server logs
ies-manage logs monitoring  # Docker monitoring logs

# Maintenance operations
ies-manage update     # Update IES application
ies-manage backup     # Create system backup
```

### System Monitoring
```bash
# Inside container
ies-monitor          # System status overview
htop                # Process monitoring
journalctl -u ies-analyzer  # Service logs
docker compose ps    # Monitoring container status
```

## 🔒 Security Configuration

### Network Security
- **Firewall Rules**: Only 192.168.0.0/24 network access allowed
- **SSL/TLS**: All HTTP traffic redirected to HTTPS
- **Access Control**: IP-based restrictions in Nginx
- **Port Management**: Only necessary ports exposed

### Authentication & Access
- **SSH**: Password authentication enabled by default
- **Web Interface**: No additional authentication (add if needed)
- **Monitoring**: Grafana admin account with default password
- **System**: Root access with configured password

### Security Hardening Recommendations
```bash
# Inside container - implement after installation
# 1. Change default passwords
passwd root
# Edit Grafana admin password in docker-compose.yml

# 2. Configure SSH key authentication
mkdir -p ~/.ssh
# Add your public key to ~/.ssh/authorized_keys
# Disable password authentication in /etc/ssh/sshd_config

# 3. Update SSL certificates
# Replace self-signed certificates in /etc/nginx/ssl/

# 4. Enable additional logging
# Configure rsyslog for centralized logging

# 5. Regular security updates
apt-get update && apt-get upgrade -y
```

## 📊 Monitoring & Dashboards

### Grafana Dashboards
Access Grafana at `http://your-ip:3000` with admin/admin123:

1. **IES Application Dashboard**
   - HTTP request rates and response times
   - Application errors and performance metrics
   - Database query performance
   - User activity and session tracking

2. **System Overview Dashboard**
   - CPU, memory, and disk utilization
   - Network traffic and connections
   - Container resource usage
   - System health indicators

3. **Security Dashboard**
   - Failed login attempts
   - Firewall blocks
   - Access patterns
   - Security event correlation

### Custom Metrics
The application exposes custom metrics at `/metrics`:
- Dataset access patterns
- Processing times by operation type
- User behavior analytics
- Business-specific KPIs

## 🛠️ Customization

### Application Configuration
```bash
# Edit application settings
nano /opt/IES/config/app_config.py

# Modify environment variables
nano /opt/IES/.env

# Update Python dependencies
cd /opt/IES
source ies_env/bin/activate
pip install additional-package
```

### Web Server Configuration
```bash
# Modify Nginx settings
nano /etc/nginx/sites-available/ies-analyzer

# Test configuration
nginx -t

# Reload configuration
systemctl reload nginx
```

### Monitoring Configuration
```bash
# Update Prometheus targets
nano /opt/monitoring/prometheus/prometheus.yml

# Modify Grafana settings
nano /opt/monitoring/docker-compose.yml

# Restart monitoring stack
cd /opt/monitoring
docker compose restart
```

## 🔧 Troubleshooting

### Common Issues

**Container Won't Start:**
```bash
# Check container logs
journalctl -u lxc@351

# Verify container configuration
pct config 351

# Check resource availability
pvesm status
```

**Application Not Accessible:**
```bash
# Inside container, check services
ies-manage status
systemctl status ies-analyzer nginx

# Check network connectivity
curl -I http://localhost:8000/health

# Verify firewall rules
ufw status verbose
```

**Monitoring Services Down:**
```bash
# Check Docker services
cd /opt/monitoring
docker compose ps
docker compose logs

# Restart monitoring stack
docker compose down
docker compose up -d
```

**SSL Certificate Issues:**
```bash
# Verify certificate validity
openssl x509 -in /etc/nginx/ssl/server.crt -text -noout

# Regenerate self-signed certificate
cd /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=your-domain"

# Reload Nginx
systemctl reload nginx
```

### Log Locations

| Component | Log Location | Access Method |
|-----------|--------------|---------------|
| **Application** | `/opt/IES/logs/` | `ies-manage logs app` |
| **Nginx** | `/var/log/nginx/` | `journalctl -u nginx` |
| **System** | `journalctl` | `ies-manage logs` |
| **Container** | Proxmox host | `journalctl -u lxc@351` |
| **Monitoring** | Docker logs | `ies-manage logs monitoring` |

### Performance Tuning

```bash
# Inside container - optimize for larger datasets
# 1. Increase container resources (from Proxmox host)
pct set 351 -memory 4096 -cores 4

# 2. Optimize Python application
export PYTHONUNBUFFERED=1
export OMP_NUM_THREADS=4

# 3. Tune Nginx for high traffic
# Edit /etc/nginx/nginx.conf
worker_processes auto;
worker_connections 1024;

# 4. Optimize monitoring retention
# Edit /opt/monitoring/prometheus/prometheus.yml
storage.tsdb.retention.time=15d  # Reduce from 30d if needed
```

## 📦 Backup & Recovery

### Automated Backups
```bash
# Inside container
ies-manage backup

# Scheduled backups with cron
echo "0 2 * * * /usr/local/bin/ies-manage backup" | crontab -
```

### Container-Level Backup
```bash
# From Proxmox host
vzdump 351 --storage local --compress gzip

# Restore from backup
pct restore 351 /var/lib/vz/dump/vzdump-lxc-351-*.tar.gz
```

### Data Migration
```bash
# Export application data
cd /opt/IES
tar -czf /tmp/ies-data-$(date +%Y%m%d).tar.gz data/ config/ logs/

# Import to new container
scp /tmp/ies-data-*.tar.gz root@new-host:/tmp/
# Extract and restore on target system
```

## 🔄 Updates & Maintenance

### Application Updates
```bash
# Inside container
ies-manage update

# Manual update process
cd /opt/IES
git pull origin main
source ies_env/bin/activate
pip install -r requirements.txt
systemctl restart ies-analyzer
```

### System Updates
```bash
# Inside container
apt-get update
apt-get upgrade -y
apt-get autoremove -y

# Update monitoring stack
cd /opt/monitoring
docker compose pull
docker compose up -d
```

### Maintenance Schedule
- **Daily**: Check service status and logs
- **Weekly**: Review monitoring dashboards and alerts
- **Monthly**: Apply system updates and security patches
- **Quarterly**: Review and update SSL certificates
- **Annually**: Full backup and disaster recovery testing

## 📞 Support & Documentation

### Getting Help
1. **Check Logs**: Use `ies-manage logs` to identify issues
2. **System Status**: Run `ies-monitor` for overview
3. **Service Status**: Use `ies-manage status` for service health
4. **Container Access**: Use `pct enter 351` from Proxmox host

### Documentation Locations
- **Installation Info**: `/root/installation-info.txt` (inside container)
- **Configuration**: `/root/ies-config.conf` (inside container)  
- **Application Docs**: `/opt/IES/README.md`
- **Monitoring Setup**: `/opt/monitoring/README.md`

### Community Resources
- **GitHub Repository**: https://github.com/DXCSithlordPadawan/IES
- **Issue Tracker**: Report bugs and feature requests
- **Documentation**: Comprehensive guides and tutorials
- **Community Forum**: User discussions and support

## 🚀 Advanced Deployment Options

### High Availability Setup
```bash
# Create multiple containers for load balancing
for i in {351..353}; do
  CT_ID=$i IP=192.168.0.$((200+$i-351)) ./deploy-ies-lxc.sh --non-interactive
done

# Configure load balancer (HAProxy/Nginx) separately
```

### Production Environment
```bash
# Enhanced security and performance
./deploy-ies-lxc.sh \
  --ct-id 300 \
  --ip 192.168.0.100 \
  --domain ies-production.company.com \
  --storage "ssd-pool" \
  --password "$(openssl rand -base64 32)" \
  --non-interactive

# Additional hardening steps required post-installation
```

This deployment script provides a production-ready IES Military Database Analyzer installation with comprehensive monitoring, security, and management capabilities, designed specifically for Proxmox VE environments.