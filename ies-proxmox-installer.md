# IES Military Database Analyzer - Proxmox LXC Deployment

This deployment script creates a fully configured LXC container with the IES Military Database Analyzer, including monitoring, security, and web interface.

## Quick Installation

### Method 1: Download and Run (Recommended)
```bash
# On your Proxmox host console
wget -qO- https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/deploy-ies-lxc.sh | bash
```

### Method 2: Manual Download
```bash
# Download the script
wget https://raw.githubusercontent.com/DXCSithlordPadawan/IES/main/deploy-ies-lxc.sh

# Make executable
chmod +x deploy-ies-lxc.sh

# Run with default settings
./deploy-ies-lxc.sh

# Or run with custom parameters
./deploy-ies-lxc.sh --ct-id 352 --ip 192.168.0.201 --non-interactive
```

## Default Configuration

| Setting | Default Value | Description |
|---------|---------------|-------------|
| Container ID | 351 | LXC container ID |
| Container Name | ies-analyzer | Hostname and container name |
| IP Address | 192.168.0.200 | Static IP address |
| Gateway | 192.168.0.1 | Network gateway |
| DNS Server | 192.168.0.110 | DNS resolver |
| Storage | pve1 | Proxmox storage location |
| Root Password | BobTheBigRedBus-0 | Default root password |
| SSH Access | Enabled | Remote SSH access |
| Disk Size | 8GB | Root filesystem size |
| RAM | 2048MB | Memory allocation |
| CPU Cores | 2 | vCPU cores |
| Domain | ies-analyzer.local | Application domain |
| Cert Server | 192.168.0.122 | Internal certificate server |

## Features Included

### Core Application
- IES Military Database Analyzer v3
- Python 3.11 runtime environment
- Flask web framework
- Gunicorn WSGI server
- Systemd service management

### Web Infrastructure
- Nginx reverse proxy
- SSL/TLS termination (self-signed certificates)
- HTTP to HTTPS redirection
- Security headers and access controls

### Monitoring Stack
- Prometheus metrics collection (port 9090)
- Grafana dashboards (port 3000, admin/admin123)
- Node Exporter system metrics
- Application performance monitoring

### Security
- UFW firewall (192.168.0.0/24 access only)
- Fail2Ban intrusion prevention
- SSL/TLS encryption
- Network isolation

### Management Tools
- `ies-manage` - Service management utility
- `ies-monitor` - System status monitoring
- Automated backup capabilities
- Update management

## Command Line Options

```bash
./deploy-ies-lxc.sh [options]

Options:
  --ct-id <id>          Container ID (default: 351)
  --ip <address>        IP address (default: 192.168.0.200)
  --gateway <address>   Gateway (default: 192.168.0.1)
  --dns <address>       DNS server (default: 192.168.0.110)
  --storage <name>      Storage name (default: pve1)
  --password <pass>     Root password (default: BobTheBigRedBus-0)
  --cert-server <ip>    Certificate server (default: 192.168.0.122)
  --domain <domain>     Domain name (default: ies-analyzer.local)
  --non-interactive     Skip configuration menu
  --help               Show help
```

## Usage Examples

### Basic Installation
```bash
# Use all defaults
./deploy-ies-lxc.sh --non-interactive
```

### Custom Configuration
```bash
# Custom IP and container ID
./deploy-ies-lxc.sh --ct-id 355 --ip 192.168.0.205 --domain ies-production.local
```

### Production Setup
```bash
# Production deployment with custom settings
./deploy-ies-lxc.sh \
  --ct-id 300 \
  --ip 192.168.0.100 \
  --domain ies-analyzer.company.com \
  --password "SecurePassword123!" \
  --storage "ssd-pool" \
  --non-interactive
```

## Access URLs

After deployment, the application will be available at:

- **Main Application**: https://192.168.0.200 (or your configured IP)
- **Grafana Monitoring**: http://192.168.0.200:3000 (admin/admin123)
- **Prometheus Metrics**: http://192.168.0.200:9090
- **SSH Access**: `ssh root@192.168.0.200` (if enabled)

## Post-Installation Management

### Container Management (Proxmox Host)
```bash
# Start/stop container
pct start 351
pct stop 351

# Access container console
pct enter 351

# Container status
pct status 351
```

### Application Management (Inside Container)
```bash
# Service management
ies-manage start      # Start all services
ies-manage stop       # Stop all services
ies-manage restart    # Restart all services
ies-manage status     # Show service status

# Monitoring
ies-manage logs app   # Application logs
ies-manage logs nginx # Web server logs
ies-monitor          # System status

# Maintenance
ies-manage update     # Update application
ies-manage backup     # Create backup
```

## Customization

### SSL Certificates
Replace self-signed certificates with proper ones:
```bash
# Inside container
cp your-cert.crt /etc/nginx/ssl/server.crt
cp your-cert.key /etc/nginx/ssl/server.key
systemctl reload nginx
```

### Application Configuration
```bash
# Edit application settings
nano /opt/IES/config/app_config.py

# Restart application
ies-manage restart
```

### Firewall Rules
```bash
# Add custom firewall rules
ufw allow from 10.0.0.0/8 to any port 443
ufw reload
```

## Troubleshooting

### Common Issues

**Container won't start:**
```bash
# Check container configuration
pct config 351

# View container logs
journalctl -u lxc@351
```

**Application not accessible:**
```bash
# Inside container, check services
ies-manage status
systemctl status ies-analyzer nginx

# Check firewall
ufw status
```

**Network connectivity issues:**
```bash
# Test network from container
pct exec 351 -- ping 8.8.8.8

# Check IP configuration
pct exec 351 -- ip addr show
```

### Log Locations

- Application logs: `/opt/IES/logs/`
- Nginx logs: `/var/log/nginx/`
- System logs: `journalctl -u ies-analyzer`
- Container logs: `journalctl -u lxc@351` (from Proxmox host)

## Security Considerations

### Default Security Settings
- Firewall restricts access to 192.168.0.0/24 network
- Fail2Ban protection against brute force attacks
- SSL/TLS encryption for web traffic
- No unnecessary services enabled

### Recommended Security Enhancements
1. Change default root password immediately
2. Replace self-signed SSL certificates
3. Configure proper DNS entries
4. Set up monitoring alerts
5. Regular security updates
6. Backup encryption

### Network Security
The container is configured to only accept connections from:
- 192.168.0.0/24 (local network)
- 127.0.0.1 (localhost)

All other connections are blocked by default.

## Backup and Recovery

### Automated Backups
```bash
# Inside container
ies-manage backup
```

### Manual Container Backup
```bash
# From Proxmox host
vzdump 351 --storage local --compress gzip

# Restore from backup
pct restore 351 /var/lib/vz/dump/vzdump-lxc-351-*.tar.gz
```

## Monitoring and Alerts

### Grafana Dashboard
Access Grafana at http://your-ip:3000 (admin/admin123) to view:
- Application performance metrics
- System resource usage
- Network traffic analysis
- Custom alerts and notifications

### Prometheus Metrics
Available at http://your-ip:9090:
- Application-specific metrics
- System metrics via Node Exporter
- Custom business metrics

## Support and Updates

### Updating the Application
```bash
# Inside container
ies-manage update
```

### Getting Support
1. Check application logs: `ies-manage logs app`
2. Review system status: `ies-monitor`
3. Check container status from Proxmox host: `pct status 351`
4. Access container console: `pct enter 351`

For issues with the deployment script or application, refer to the GitHub repository or contact the development team.