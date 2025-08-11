# Ubuntu Server Setup Scripts

Automated server setup scripts for Ubuntu 22.04/24.04 LTS, optimized for Docker-based deployments with Kamal on Hetzner VPS.

## 🚀 Quick Start

```bash
# Download and run the setup script
wget https://raw.githubusercontent.com/yourusername/ubuntu-scripts/main/setup.sh
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
- **Firewall**: UFW with Docker-aware rules
- **Fail2ban**: Automatic IP banning for failed login attempts
- **Kernel Security**: Hardened sysctl parameters
- **Automatic Updates**: Unattended security updates enabled

### Docker Environment
- Docker CE installation with official GPG keys
- Docker Compose v2 support
- Proper user permissions (docker group)
- Docker security best practices

### System Configuration
- Non-root deploy user with limited sudo privileges
- Swap file configuration (2GB default)
- Essential packages installation
- System monitoring and health checks
- Log rotation setup

### Rails/Kamal Ready
- Optimized for Ruby on Rails deployments
- Compatible with Kamal deployment tool
- PostgreSQL/Redis ready
- Nginx configuration support

## 🛠️ Installation

### Interactive Mode (Recommended)

Run the script and follow the prompts:

```bash
sudo ./setup.sh
```

You'll be asked for:
- Your SSH public key (required)
- Custom SSH port (optional, default: 22)
- Deploy username (optional, default: deploy)

### Non-Interactive Mode

Set environment variables before running:

```bash
export DEPLOY_USER="deploy"
export SSH_PORT="2222"
export YOUR_SSH_PUBLIC_KEY="ssh-ed25519 AAAA..."
sudo -E ./setup.sh
```

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
| Deploy User | `deploy` | Non-root user for deployments |
| SSH Port | `22` | SSH service port (recommend changing) |
| Swap Size | `2G` | Swap file size |
| Docker Version | Latest CE | Docker Community Edition |

### Post-Installation

After successful installation:

1. **Test SSH access** in a new terminal:
   ```bash
   ssh -p [PORT] deploy@[SERVER_IP]
   ```

2. **Save credentials** displayed at the end of setup:
   - Deploy user password (if needed for sudo)
   - Server configuration summary

3. **Deploy your application** using Kamal or Docker Compose

## 🔒 Security Features

### SSH Hardening
- Disabled root login
- Password authentication disabled
- Key-only authentication
- Rate limiting with fail2ban
- Custom port support

### Firewall Rules
- Default deny incoming
- Allow SSH, HTTP, HTTPS
- Docker-aware configuration
- DDoS protection

### System Hardening
- Kernel parameter tuning
- IP spoofing protection
- SYN flood protection
- ICMP redirect blocking

## 📊 Monitoring

The setup includes automated health monitoring:

- System health checks every 6 hours
- Disk usage monitoring
- Memory usage tracking
- Docker service status
- Critical service monitoring

Health reports are saved to `/var/log/health-check.log`

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

The deploy user has limited sudo access for:
- `systemctl restart docker`
- `journalctl -u docker`

For other operations, use root or modify `/etc/sudoers.d/deploy`

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
sudo ./setup.sh --dry-run  # Coming soon
```

## ⚠️ Important Notes

- **Always test** on a non-production server first
- **Create backups** before running on existing servers
- **Keep your SSH key secure** - it's your only access method
- **Save the deploy password** shown during setup
- **Test SSH access** before closing your root session

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- Optimized for Hetzner Cloud VPS
- Compatible with Kamal deployment tool
- Based on Ubuntu security best practices

## 📞 Support

For issues or questions:
- Open an issue on GitHub
- Check the [TODO.md](TODO.md) for known issues
- Review logs in `/var/log/` for debugging

---

**Version:** 1.0.0  
**Tested on:** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS  
**Last Updated:** 2025