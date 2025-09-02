# IES Military Database Analyzer - Unified Proxmox Deployment

This repository provides two consolidated, production-ready deployment scripts for the IES Military Database Analyzer on Proxmox VE, combining and rationalizing multiple previous scripts into streamlined solutions.

## 📦 What You Get

### Two Optimized Scripts
1. **`ies-complete-deploy.sh`** - Full-featured deployment with interactive configuration
2. **`quick-install.sh`** - One-line installer for rapid deployment

### All Previous Fixes Integrated
- ✅ APT repository configuration issues resolved
- ✅ Python dependency conflicts eliminated  
- ✅ Application argument compatibility fixed
- ✅ SSL certificate generation improved
- ✅ Service management enhanced
- ✅ Network connectivity validation added
- ✅ Comprehensive error handling implemented

## 🚀 Quick Start

### Option 1: One-Line Installation
```bash
# Default configuration (Container 351, IP 192.168.0.200)
bash <(curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install.sh)

# Custom configuration using environment variables
export CT_ID=352 IP=192.168.0.201 DOMAIN=ies-prod.local
bash <(curl -sSL https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/quick-install.sh)
```

### Option 2: Full Control Installation
```bash
# Download comprehensive installer
wget https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/ies-complete-deploy.sh
chmod +x ies-complete-deploy.sh

# Interactive installation (recommended for production)
./ies-complete-deploy.sh

# Non-interactive with custom parameters
./ies-complete-deploy.sh --ct-id 350 --ip 192.168.0.199 --domain ies-dev.local --non-interactive
```

## 📋 Default Configuration

| Setting | Default | Override |
|---------|---------|----------|
| Container ID | 351 | `--ct-id` or `CT_ID` |
| IP Address | 192.168.0.200 | `--ip` or `IP` |
| Gateway | 192.168.0.1 | `--gateway` or `GATEWAY` |
| DNS | 192.168.0.110 | `--dns` or `DNS` |
| Storage | local-lvm | `--storage` or `STORAGE` |
| Password | BobTheBigRedBus-0 | `--password` or `PASSWORD` |
| Domain | ies-analyzer.local | `--domain` or `DOMAIN` |

## 🎯 Complete Feature Set

### Core Application
- IES Military Database Analyzer v3.0 with metrics support
- Python 3.11 virtual environment with all dependencies
- Flask web framework with enhanced UI
- Systemd service integration with health checks

### Web Infrastructure  
- Nginx reverse proxy with SSL/TLS termination
- HTTP to HTTPS redirection
- Security headers and access controls
- Network-based restrictions (192.168.0.0/24 only)

### Monitoring Stack
- **Prometheus** (port 9090) - Metrics collection and alerting
- **Grafana** (port 3000) - Visualization dashboards (admin/admin123)
- **Node Exporter** - System metrics
- **Custom Metrics** - Application-specific monitoring

### Security Features
- UFW firewall configuration
- Fail2Ban intrusion prevention
- SSL/TLS encryption (self-signed certificates)
- Container isolation and privilege separation

### Management Tools
- **`ies-manage`** - Comprehensive service management
- **`ies-monitor`** - Real-time system status
- **`ies-emergency-repair`** - Automated problem resolution
- Backup and update capabilities

## 🌐 Access Your Deployment

After installation completes, access your services:

| Service | URL | Credentials |
|---------|-----|-------------|
| **Main Application** | https://192.168.0.200 | None |
| **Grafana** | http://192.168.0.200:3000 | admin/admin123 |
| **Prometheus** | http://192.168.0.200:9090 | None |
| **SSH** | ssh root@192.168.0.200 | BobTheBigRedBus-0 |

## 🛠️ Management Commands

### From Proxmox Host
```bash
pct enter 351                    # Access container
pct start/stop/restart 351      # Control container
pct set 351 -memory 4096        # Adjust resources
```

### Inside Container
```bash
# Service management
ies-manage start                 # Start all services
ies-manage restart               # Restart all services  
ies-manage status                # Check service status
ies-manage test                  # Test all endpoints

# Troubleshooting
ies-monitor                      # System dashboard
ies-manage logs app              # View application logs
ies-manage repair                # Auto-repair issues
ies-emergency-repair             # Comprehensive fix

# Maintenance  
ies-manage update                # Update application
ies-manage backup                # Create backup
```

## 🔧 Problem Resolution

The scripts include automated solutions for all known issues:

### APT Repository Problems
```bash
# Automatic detection and repair of Docker repository issues
# Manual fix: ies-manage fix-apt
```

### Python Dependency Issues  
```bash
# Sequential installation prevents conflicts
# Manual fix: ies-manage fix-deps
```

### Service Startup Problems
```bash  
# Enhanced systemd services with health checks
# Manual fix: ies-manage repair
```

### SSL Certificate Issues
```bash
# Proper certificate generation with SAN extensions  
# Certificates regenerated automatically during repair
```

## 📊 Monitoring and Alerts

### Grafana Dashboards (http://your-ip:3000)
- Application performance metrics
- System resource monitoring  
- Security event tracking
- Custom business metrics

### Prometheus Metrics (http://your-ip:9090)
```
ies_http_requests_total         # Request counters
ies_http_request_duration_seconds  # Response times  
ies_system_cpu_percent          # CPU usage
ies_system_memory_bytes         # Memory usage
ies_application_status          # Health status
```

## 🔒 Security Features

### Network Security
- Firewall restricts access to 192.168.0.0/24 network only
- All HTTP traffic automatically redirected to HTTPS
- Modern TLS protocols with secure cipher suites
- IP-based access controls in Nginx

### System Security
- Container isolation and unprivileged execution
- Fail2Ban protection against brute force attacks
- Service privilege separation
- Comprehensive access logging

## 📈 Deployment Examples

### Development Environment
```bash
export CT_ID=399 IP=192.168.0.199 DOMAIN=ies-dev.local
./quick-install.sh
```

### Production Environment
```bash
./ies-complete-deploy.sh \
  --ct-id 300 \
  --ip 192.168.0.100 \
  --domain ies-production.company.com \
  --password "$(openssl rand -base64 32)" \
  --non-interactive
```

### High Availability Setup
```bash
# Deploy multiple containers
for i in {351..353}; do
  CT_ID=$i IP=192.168.0.$((200+$i-351)) ./ies-complete-deploy.sh --non-interactive
done
```

## 🆘 Emergency Support

### Quick Diagnosis
```bash
ies-manage test                  # Test all endpoints
ies-monitor                      # System overview
ies-manage status                # Service status
```

### Automated Recovery  
```bash
ies-emergency-repair             # Fix all known issues
ies-manage repair                # Standard repair
ies-manage fix-deps              # Fix Python issues only
```

### Manual Recovery
```bash
# If container is unresponsive
pct stop 351 && pct start 351
pct enter 351
ies-emergency-repair
```

## 📚 Documentation Structure

- **Installation**: This README and inline help (`--help`)
- **Management**: Built-in command help (`ies-manage` without args)  
- **Configuration**: `/root/ies-deployment-info.txt` (inside container)
- **Logs**: `/opt/IES/logs/` and `journalctl -u ies-analyzer`

## 🎯 Key Improvements Over Original Scripts

### Consolidated Functionality
- Merged 8 separate scripts into 2 optimized versions
- Combined all emergency repair functions
- Unified configuration and management approaches

### Enhanced Reliability  
- Comprehensive error handling and recovery
- Automated problem detection and resolution
- Sequential dependency installation prevents conflicts

### Improved User Experience
- Single command deployment options
- Interactive configuration menus
- Clear status reporting and documentation

### Production Readiness
- Complete monitoring and security stack
- Automated backup and update procedures  
- Comprehensive management utilities

## 🔄 Version History

- **v2.0** - Consolidated deployment with all fixes integrated
- **v1.x** - Multiple separate scripts (deprecated)

## ✅ Validation Checklist

After deployment, verify:
- [ ] `ies-manage test` shows all endpoints responding (200)
- [ ] `ies-monitor` displays healthy system status  
- [ ] Application accessible at https://your-ip
- [ ] Grafana dashboard available at http://your-ip:3000
- [ ] All services active in `ies-manage status`
- [ ] Check the datetime sync 'dpkg-reconfigure tzdata'

This unified deployment solution provides everything needed for a production-ready IES Military Database Analyzer installation with comprehensive monitoring, security, and management capabilities.
