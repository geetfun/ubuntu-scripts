# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains automated Ubuntu server setup scripts optimized for Docker-based deployments with Kamal on Hetzner VPS. The main component is a bash script that configures security, Docker, and system settings on fresh Ubuntu 22.04/24.04 LTS installations.

## Architecture

### Main Components

- **setup.sh**: Single comprehensive bash script that handles the entire server provisioning process
  - Interactive prompts for SSH key, port, and username configuration
  - Modular functions for different setup phases (security, Docker, monitoring)
  - Extensive error handling with retry logic for network operations
  - Colored output and comprehensive logging to `/var/log/server-setup.log`

### Key Setup Phases

1. **User Input & Validation** (lines 62-99): Collects SSH key, custom port, and username
2. **System Update** (lines 101-134): Updates packages with retry logic
3. **User Creation** (lines 136-170): Creates deploy user with SSH access
4. **SSH Hardening** (lines 172-238): Configures secure SSH settings
5. **Firewall Setup** (lines 240-280): UFW configuration with Docker compatibility
6. **Fail2ban** (lines 282-330): Intrusion prevention setup
7. **Docker Installation** (lines 332-380): Docker CE and Docker Compose installation
8. **System Tuning** (lines 382-450): Kernel parameters, swap, and monitoring
9. **Health Monitoring** (lines 452-550): Automated health check cron job

## Development Commands

### Testing the Script

```bash
# Run setup script (requires root)
sudo ./setup.sh

# Check script syntax
bash -n setup.sh

# Validate with shellcheck (if installed)
shellcheck setup.sh
```

### Monitoring Setup Progress

```bash
# Watch the setup log in real-time
tail -f /var/log/server-setup.log

# Check health monitoring logs (after setup)
tail -f /var/log/health-check.log
```

## Important Considerations

- The script modifies critical system settings including SSH, firewall, and kernel parameters
- Always test on non-production servers first
- SSH key is mandatory - the script will exit without it
- Default SSH port is 22 but changing it is strongly recommended for security
- Deploy user gets limited sudo access for Docker operations only
- Health checks run every 6 hours via cron

## Error Handling Patterns

The script uses consistent error handling:
- `set -euo pipefail` for strict error checking
- Retry function for network operations (3 attempts with 5-second delays)
- All operations logged to `/var/log/server-setup.log`
- Colored output functions: `print_status`, `print_error`, `print_warning`

## Security Features

- SSH: Key-only authentication, disabled root login, rate limiting
- Firewall: Default deny with specific allow rules for SSH/HTTP/HTTPS
- Fail2ban: Automatic IP banning for failed login attempts
- Kernel hardening: IP spoofing protection, SYN flood protection, ICMP redirect blocking
- Automatic security updates via unattended-upgrades