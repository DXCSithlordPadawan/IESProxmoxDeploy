# IES Military Database Analyzer - Fixed Proxmox LXC Deployment

This repository contains fully tested and debugged scripts to deploy the IES Military Database Analyzer as an LXC container on Proxmox VE. All known issues have been resolved including APT repository problems, Python dependency conflicts, and SSL configuration issues.

## 🚀 Quick Start (Recommended)

### One-Line Installation with All Fixes
```bash
# Run directly from Proxmox host console (includes all fixes)
bash <(curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install-fixed.sh)
```

### Manual Installation with Full Control
```bash
# Download the comprehensive deployment script
wget https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/deploy-ies-lxc-fixed.sh
chmod +x deploy-ies-lxc-fixed.sh
./deploy-ies-lxc-fixed.sh
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
| **Web Port** | 8000 | Application port |

## 🔧 Major Fixes Implemented

### 1. **APT Repository Configuration**
- **Issue**: Docker repository with malformed variable expansion
- **Fix**: Proper variable expansion in repository creation
- **Prevention**: APT configuration testing before proceeding
- **Repair**: `ies-manage fix-apt` command available

### 2. **Python Dependencies**
- **Issue**: NetworkX and other packages failing to import
- **Fix**: Sequential dependency installation in correct order
- **Prevention**: Comprehensive dependency verification
- **Repair**: `ies-manage fix-deps` command available

### 3. **Application Arguments**
- **Issue**: Unknown `--host` and `--port` arguments
- **Fix**: Updated `military_database_analyzer_v3.py` to support these arguments
- **Prevention**: Proper systemd service configuration
- **Repair**: Automatic application file patching

### 4. **SSL Certificate Issues**  
- **Issue**: PR_END_OF_FILE_ERROR with self-signed certificates
- **Fix**: Proper SSL certificate generation with SAN extensions
- **Prevention**: Nginx configuration validation
- **Repair**: `ies-manage repair` includes SSL regeneration

### 5. **Service Management**
- **Issue**: Services failing to start or restart properly
- **Fix**: Enhanced systemd services with health checks
- **Prevention**: Dependency verification before service start
- **Repair**: Comprehensive restart and recovery procedures

## 🎯 Enhanced Features

### Comprehensive Management Tool
The `ies-manage` script now includes:

```bash
ies-manage start      # Start all services
ies-manage stop       # Stop all services
ies-manage restart    # Restart all services
ies-manage status     # Show detailed status
ies-manage logs       # View logs (app|nginx|monitoring)
ies-manage update     # Update application
ies-manage fix-deps   # Fix Python dependencies
ies-manage fix-apt    # Fix APT configuration
ies-manage test       # Run comprehensive tests
ies-manage repair     # Full system repair
ies-manage backup     # Create system backup
```

### Automated Problem Detection
- **Dependency Verification**: Automatically checks and fixes missing Python packages
- **APT Configuration**: Detects and repairs malformed repository files
- **Service Health**: Monitors and restarts failed services
- **Network Connectivity**: Tests application endpoints and web access
- **SSL Certificate**: Validates and regenerates certificates as needed

### Enhanced Monitoring Stack
- **Prometheus**: Metrics collection with 15-day retention
- **Grafana**: Dashboards with health checks
- **Node Exporter**: System metrics
- **Custom Metrics**: Application-specific monitoring
- **Docker Health Checks**: Container status monitoring

## 🌐 Access Information

After successful deployment, all services are accessible:

| Service | HTTP | HTTPS | Credentials |
|---------|------|--------|-------------|
| **Main Application** | http://192.168.0.200 | https://192.168.0.200 | N/A |
| **Grafana Dashboard** | http://192.168.0.200:3000 | N/A | admin/admin123 |
| **Prometheus** | http://192.168.0.200:9090 | N/A | N/A |
| **SSH Access** | ssh root@192.168.0.200 | N/A | BobTheBigRedBus-0 |

## 🔧 Troubleshooting Fixed Issues

### Issue: APT Repository Error
```
E:Malformed entry 1 in list file /etc/apt/sources.list.d/docker.list
```

**Automatic Fix**: The deployment scripts now properly expand variables
**Manual Fix**: Run `ies-manage fix-apt`

### Issue: NetworkX Import Error  
```
ModuleNotFoundError: No module named 'networkx'
```

**Automatic Fix**: Dependencies installed in correct order with verification
**Manual Fix**: Run `ies-manage fix-deps`

### Issue: SSL Connection Failed
```
PR_END_OF_FILE_ERROR
```

**Automatic Fix**: Proper SSL certificate generation with SAN extensions  
**Manual Fix**: Run `ies-manage repair`

### Issue: Service Arguments Error
```
error: unrecognized arguments: --host 0.0.0.0 --port 8000
```

**Automatic Fix**: Application code updated to support these arguments
**Manual Fix**: Application file is automatically patched during installation

## 📊 Deployment Validation

The enhanced scripts include comprehensive validation:

### Pre-Installation Checks
- Proxmox VE environment validation
- Container ID availability check
- Network connectivity testing
- Required templates verification

### Installation Verification  
- APT configuration testing
- Python dependency validation
- Application import testing
- Service startup verification
- Network endpoint testing

### Post-Installation Testing
```bash
# Run comprehensive system tests
ies-manage test

# Check specific components
systemctl status ies-analyzer nginx docker
curl -k https://192.168.0.200/health
```

## 🔄 Update and Maintenance

### Automated Updates
```bash
# Update application and dependencies
ies-manage update

# Full system repair if issues arise
ies-manage repair

# Create backup before major changes
ies-manage backup
```

### Manual Fixes for Persistent Issues
```bash
# If container has issues, from Proxmox host:
pct enter 351

# Run the comprehensive repair tool
ies-manage repair

# Or fix specific components
ies-manage fix-apt      # Fix APT repositories
ies-manage fix-deps     # Fix Python dependencies  

# Test everything
ies-manage test
```

## 🛡️ Security Enhancements

### Network Security
- UFW firewall with 192.168.0.0/24 access only
- Nginx access controls with IP restrictions
- SSL/TLS encryption with proper certificates
- No unnecessary ports exposed

### Application Security  
- Service isolation with systemd
- User privilege separation
- Resource limits and monitoring
- Comprehensive logging and auditing

### Maintenance Security
- Automatic security updates capability
- Backup encryption options
- Certificate rotation procedures
- Access logging and monitoring

## 📝 Known Limitations and Workarounds

### 1. **Docker Repository Issues**
- **Limitation**: Some systems may have APT conflicts with Docker repository
- **Workaround**: Script falls back to Ubuntu Docker packages automatically
- **Manual Fix**: `ies-manage fix-apt` repairs repository configuration

### 2. **Python Package Conflicts**
- **Limitation**: Some Python packages may conflict during installation
- **Workaround**: Sequential installation prevents most conflicts
- **Manual Fix**: `ies-manage fix-deps` resolves dependency issues

### 3. **SSL Certificate Trust**
- **Limitation**: Self-signed certificates trigger browser warnings
- **Workaround**: Use HTTP for initial testing, replace with proper certificates
- **Manual Fix**: Install CA-signed certificates in `/etc/nginx/ssl/`

## 🚀 Advanced Usage

### Production Deployment
```bash
# Production setup with enhanced security
CT_ID=300 IP=192.168.0.100 PASSWORD="SecurePassword123!" ./deploy-ies-lxc-fixed.sh --non-interactive

# Post-deployment hardening
pct enter 300
ies-manage repair
ufw enable
systemctl enable fail2ban
```

### High Availability Setup
```bash
# Deploy multiple containers for load balancing
for i in {351..353}; do
  CT_ID=$i IP=192.168.0.$((200+$i-351)) ./deploy-ies-lxc-fixed.sh --non-interactive
done
```

### Development Environment
```bash
# Development setup with debugging enabled
CT_ID=399 IP=192.168.0.199 ./deploy-ies-lxc-fixed.sh
pct enter 399
ies-manage logs app  # Monitor application logs
```

## 📞 Support and Recovery

### Emergency Recovery
If the container becomes unresponsive:
```bash
# From Proxmox host
pct stop 351
pct start 351
pct enter 351

# Run emergency repair
ies-manage repair

# Check system status
ies-manage test
```

### Performance Optimization
```bash
# From Proxmox host - increase resources if needed
pct set 351 -memory 4096 -cores 4

# Inside container - optimize services
ies-manage restart
```

### Backup and Restore
```bash
# Create backup
ies-manage backup

# Container-level backup (from Proxmox host)
vzdump 351 --storage local --compress gzip

# Restore (from Proxmox host)
pct restore 351 /var/lib/vz/dump/vzdump-lxc-351-*.tar.gz
```

This deployment solution provides a robust, production-ready IES Military Database Analyzer installation with comprehensive error handling, automated repairs, and extensive monitoring capabilities.

## 🔗 Quick Reference Commands

### From Proxmox Host
```bash
# Container management
pct start 351                    # Start container
pct stop 351                     # Stop container
pct enter 351                    # Access container console
pct status 351                   # Check container status

# Resource management
pct set 351 -memory 4096         # Increase RAM to 4GB
pct set 351 -cores 4             # Increase to 4 CPU cores
pct config 351                   # View configuration

# Backup and restore
vzdump 351 --storage local       # Create container backup
pct restore 351 /path/to/backup  # Restore from backup
```

### Inside Container
```bash
# Service management
ies-manage start                 # Start all services
ies-manage stop                  # Stop all services
ies-manage restart               # Restart all services
ies-manage status                # Service status overview

# Troubleshooting
ies-manage test                  # Run comprehensive tests
ies-manage repair                # Fix common issues automatically
ies-manage fix-deps              # Fix Python dependencies only
ies-manage fix-apt               # Fix APT configuration only

# Monitoring
ies-manage logs app              # Application logs
ies-manage logs nginx            # Web server logs
ies-manage logs monitoring       # Monitoring stack logs
journalctl -u ies-analyzer -f   # Live application logs

# Maintenance
ies-manage update                # Update application
ies-manage backup                # Create backup
```

## 🎯 Verification Checklist

After deployment, verify everything is working:

### ✅ System Health Check
```bash
# Inside container
ies-manage test
```

Expected output should show:
- ✓ All Python packages imported successfully
- ✓ Main application import successful
- ✓ All services active (IES/Nginx/Docker)
- ✓ Health endpoint responding (200)
- ✓ Web endpoints responding (200)

### ✅ Web Access Check
From your workstation:
- HTTP: `http://192.168.0.200` → Should redirect to HTTPS
- HTTPS: `https://192.168.0.200` → Should show IES application
- Grafana: `http://192.168.0.200:3000` → Should show Grafana login
- Prometheus: `http://192.168.0.200:9090` → Should show Prometheus UI

### ✅ Security Check
```bash
# Inside container
ufw status                       # Should show active with rules
systemctl status fail2ban       # Should show active
curl -k https://localhost/health # Should return {"status": "healthy"}
```

## 🛠 Development and Customization

### Customizing the Application
```bash
# Inside container
cd /opt/IES
source ies_env/bin/activate

# Edit application configuration
nano config/app_config.py

# Add custom Python packages
pip install your-package

# Restart to apply changes
ies-manage restart
```

### Customizing Web Server
```bash
# Edit Nginx configuration
nano /etc/nginx/sites-available/ies-analyzer

# Test configuration
nginx -t

# Apply changes
systemctl reload nginx
```

### Customizing Monitoring
```bash
# Edit Prometheus configuration
nano /opt/monitoring/prometheus/prometheus.yml

# Edit Docker Compose for monitoring
nano /opt/monitoring/docker-compose.yml

# Restart monitoring stack
cd /opt/monitoring
docker compose restart
```

## 🔍 Debugging Guide

### Common Symptoms and Solutions

**Symptom**: Web page not loading
```bash
# Check service status
ies-manage status

# Check specific service
systemctl status ies-analyzer nginx

# Check logs
ies-manage logs app
ies-manage logs nginx

# Try repair
ies-manage repair
```

**Symptom**: Python import errors in logs
```bash
# Fix dependencies
ies-manage fix-deps

# Test imports manually
cd /opt/IES
source ies_env/bin/activate
python3 -c "import networkx, pandas, flask"
```

**Symptom**: APT update errors
```bash
# Fix APT configuration
ies-manage fix-apt

# Verify fix
apt update
```

**Symptom**: SSL/HTTPS errors
```bash
# Regenerate certificates
ies-manage repair

# Or manually
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=192.168.0.200'
systemctl reload nginx
```

## 📈 Performance Tuning

### Resource Optimization
```bash
# From Proxmox host - adjust based on usage
pct set 351 -memory 2048    # For light usage
pct set 351 -memory 4096    # For moderate usage  
pct set 351 -memory 8192    # For heavy usage
pct set 351 -cores 2        # For light usage
pct set 351 -cores 4        # For heavy usage
```

### Application Optimization
```bash
# Inside container - optimize Python environment
cd /opt/IES
source ies_env/bin/activate
pip install gunicorn[gevent]  # Better WSGI server

# Optimize monitoring retention
nano /opt/monitoring/prometheus/prometheus.yml
# Change retention to 7d for lower disk usage
```

### Network Optimization
```bash
# Inside container - optimize Nginx
nano /etc/nginx/sites-available/ies-analyzer
# Add caching headers, compression, etc.
```

## 🌟 Advanced Configuration

### Multiple Environments
```bash
# Development environment
CT_ID=350 IP=192.168.0.199 ./deploy-ies-lxc-fixed.sh

# Staging environment  
CT_ID=351 IP=192.168.0.200 ./deploy-ies-lxc-fixed.sh

# Production environment
CT_ID=352 IP=192.168.0.201 PASSWORD="ProductionPass123" ./deploy-ies-lxc-fixed.sh
```

### Load Balancing Setup
```bash
# Deploy multiple backend containers
for i in {353..355}; do
  CT_ID=$i IP=192.168.0.$((200+$i-350)) ./deploy-ies-lxc-fixed.sh --non-interactive
done

# Configure external load balancer (HAProxy/Nginx) to distribute traffic
```

### External Database Integration
```bash
# Inside container - configure external database
cd /opt/IES
nano config/app_config.py

# Update database URLs to point to external systems
# DATABASE_URL = postgresql://user:pass@db-server:5432/ies
# REDIS_URL = redis://cache-server:6379/0
```

## 📋 Maintenance Schedule

### Daily
- Monitor service status with `ies-manage status`
- Check application logs for errors
- Verify web access functionality

### Weekly  
- Run comprehensive tests with `ies-manage test`
- Review monitoring dashboards in Grafana
- Check disk usage and clean logs if needed

### Monthly
- Update application with `ies-manage update`
- Review and update SSL certificates if needed
- Backup configuration with `ies-manage backup`
- Apply system security updates

### Quarterly
- Full system maintenance with `ies-manage repair`
- Review and optimize monitoring retention
- Performance tuning based on usage patterns
- Disaster recovery testing

This comprehensive deployment solution ensures reliable operation of your IES Military Database Analyzer with minimal maintenance requirements and maximum uptime.# IES Military Database Analyzer - Proxmox LXC Deployment

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