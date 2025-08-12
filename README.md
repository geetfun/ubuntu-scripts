# Ubuntu Server Setup Scripts

Automated server setup scripts for Ubuntu 22.04/24.04 LTS, optimized for Docker-based deployments with Kamal on Hetzner VPS.

## 🚀 Quick Start

```bash
# Download and run the setup script from /tmp
cd /tmp
wget -O setup.sh https://raw.githubusercontent.com/geetfun/ubuntu-scripts/main/setup.sh
chmod +x setup.sh
sudo ./setup.sh
```

## 📋 Prerequisites

- Fresh Ubuntu 22.04 or 24.04 LTS installation
- Root access to the server
- SSH public key for authentication
- Internet connection

## ✨ Features

### Security Hardening
- **SSH Configuration**: Custom port support, key-only authentication, rate limiting
- **NO Firewall**: Script does not configure UFW (manual setup required)
- **Fail2ban**: SSH and Docker protection with automatic IP banning
- **Kernel Security**: Hardened sysctl parameters, BBR congestion control
- **Automatic Updates**: Unattended security updates enabled

### Docker Environment
- Docker CE installation with official GPG keys
- Docker Compose v2 plugin support
- Proper user permissions (docker group)
- Docker daemon security configuration
- Log rotation for container logs

### System Configuration
- Non-root deploy user with **full sudo access** (password required)
- **Intelligent swap configuration** based on RAM:
  - ≤2GB RAM: 2x RAM size
  - 2-4GB RAM: Equal to RAM size
  - 4-8GB RAM: 4GB swap
  - >8GB RAM: 4GB swap
- Essential packages installation
- System monitoring with health checks every 6 hours
- Time synchronization with Chrony

### Rails/Kamal Ready
- Optimized for Docker-based deployments
- Compatible with Kamal deployment tool
- Ready for containerized applications
- Deployment directory structure (`/home/deploy/apps`)

## 🛠️ Installation

### Interactive Mode (Recommended)

Run the script and follow the prompts:

```bash
sudo /tmp/setup.sh
```

You'll be asked for:
1. **SSH public key** (required) - Your public key for authentication
2. **SSH port** (optional, default: 22) - Custom SSH port for security
3. **Deploy username** (optional, default: deploy) - Non-root user name
4. **Password for deploy user** (required) - Will prompt for password with confirmation

The script validates:
- SSH key format (must start with ssh-ed25519, ecdsa-sha2, or ssh-rsa)
- Password strength (minimum 8 characters)
- Port range (1-65535)
- Username format (valid Linux username)

## 📁 Project Structure

```
ubuntu-scripts/
├── setup.sh        # Main setup script
├── TODO.md         # Development tasks and improvements
└── README.md       # This file
```

## 🔧 Configuration

### Default Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Deploy User | `deploy` | Non-root user with full sudo access |
| SSH Port | `22` | SSH service port (strongly recommend changing) |
| Swap Size | Dynamic | Based on RAM: ≤2GB→2x, 2-4GB→1x, >4GB→4GB |
| Docker Version | Latest CE | Docker Community Edition |
| Swappiness | `10` | Low swappiness for server workloads |
| Log Rotation | 7 days | Docker container logs retention |

### Post-Installation

After successful installation:

1. **Test SSH access** in a new terminal:
   ```bash
   ssh -p [PORT] deploy@[SERVER_IP]
   ```

2. **Save credentials** displayed at the end of setup:
   - Deploy user password (if needed for sudo)
   - Server configuration summary

3. **Configure firewall** (not automated):
   ```bash
   sudo ufw allow [SSH_PORT]/tcp
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw --force enable
   ```

4. **Deploy your application** using Kamal or Docker Compose

## 🔒 Security Features

### SSH Hardening
- Disabled root login
- Password authentication disabled (key-only)
- SSH key validation (ed25519, ecdsa-sha2, or rsa)
- Rate limiting (max 3 auth tries, 10 sessions)
- Custom port support
- Connection timeout and keep-alive settings
- Restricted to deploy user only (AllowUsers)

### Fail2ban Protection
- SSH jail (3 attempts = 1 hour ban)
- Docker jail for container auth failures
- Automatic IP banning
- Email alerts on ban actions

### System Hardening
- Kernel parameter tuning via sysctl
- IP spoofing protection (rp_filter)
- SYN flood protection (tcp_syncookies)
- ICMP redirect blocking
- BBR congestion control
- TCP optimization for performance
- Increased file descriptor limits

## 📊 Monitoring

The setup includes automated health monitoring:

- System health checks every 6 hours
- Disk usage monitoring
- Memory usage tracking
- Docker service status
- Critical service monitoring

Health checks run via cron and output warnings when thresholds (80%) are exceeded

## 🚨 Troubleshooting

### SSH Connection Issues

If you're locked out after setup:

1. Use your VPS provider's console access
2. Check SSH service status:
   ```bash
   systemctl status ssh
   ```
3. Verify firewall rules:
   ```bash
   ufw status
   ```

### Docker Issues

```bash
# Check Docker status
systemctl status docker

# View Docker logs
journalctl -u docker -f

# Test Docker installation
docker run hello-world
```

### Permission Issues

The deploy user has **full sudo access** with password authentication:
- Can run any command with `sudo`
- Can switch to root with `sudo su -`
- Password required for all sudo operations

To modify sudo permissions, edit `/etc/sudoers.d/deploy`

## 🔄 Updates and Maintenance

### System Updates

Automatic security updates are enabled. For manual updates:

```bash
sudo apt update && sudo apt upgrade
```

### Docker Updates

Docker is updated through the official repository:

```bash
sudo apt update && sudo apt upgrade docker-ce
```

## 📝 Development

See [TODO.md](TODO.md) for planned improvements and known issues.

### Contributing

1. Fork the repository
2. Create your feature branch
3. Test on a fresh Ubuntu installation
4. Submit a pull request

### Testing

Test the script on a fresh VPS:

```bash
# Create a snapshot first!
sudo /tmp/setup.sh --dry-run  # Coming soon
```

## ⚠️ Important Notes

- **Always test** on a non-production server first
- **Create backups** before running on existing servers
- **Keep your SSH key secure** - it's your only access method
- **Remember the deploy password** you set during setup
- **Test SSH access** before closing your root session

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- Optimized for Hetzner Cloud VPS
- Compatible with Kamal deployment tool
- Based on Ubuntu security best practices

## 📂 What Gets Installed

### Software Packages
- Docker CE, Docker CLI, containerd, Docker Compose plugin
- Fail2ban for intrusion prevention
- Chrony for time synchronization
- Essential tools: curl, wget, vim, htop, git, rsync
- Build tools: make, build-essential
- Security: unattended-upgrades, apt-listchanges

### Configuration Files Created
- `/etc/sudoers.d/deploy` - Sudo permissions
- `/etc/ssh/sshd_config.d/99-hardening.conf` - SSH hardening
- `/etc/fail2ban/jail.local` - Fail2ban rules
- `/etc/docker/daemon.json` - Docker configuration
- `/etc/sysctl.d/99-security.conf` - Kernel parameters
- `/etc/sysctl.d/99-swap.conf` - Swap settings
- `/usr/local/bin/server-health-check.sh` - Monitoring script
- `/root/server-setup-summary.txt` - Setup summary

### Logs
- `/var/log/server-setup.log` - Complete setup log
- System logs via journalctl

## 📞 Support

For issues or questions:
- Open an issue on GitHub
- Check the [TODO.md](TODO.md) for known issues
- Review logs in `/var/log/server-setup.log` for debugging

---

**Version:** 1.0.0
**Tested on:** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
**Last Updated:** 2025
