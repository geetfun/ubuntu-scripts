#!/bin/bash

# Run as root on a fresh Ubuntu 22.04/24.04 installation

set -euo pipefail

# Configuration variables - CHANGE THESE!
DEPLOY_USER="deploy"
DEPLOY_PASSWORD=""  # Will be set via prompt
SSH_PORT="22"  # Consider changing to non-standard port like 2222

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Retry helper with constant backoff
retry() {
    local max_attempts="$1"; shift
    local sleep_seconds="$1"; shift
    local attempt=1
    while (( attempt <= max_attempts )); do
        if "$@"; then
            return 0
        fi
        print_warning "Attempt ${attempt}/${max_attempts} failed: $*"
        (( attempt++ ))
        sleep "$sleep_seconds"
    done
    return 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

# Enable file logging (after root check to ensure permissions)
umask 027
LOG_FILE="/var/log/server-setup.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# Interactive prompt for SSH public key
print_status "SSH Key Setup"
echo ""
echo "Please paste your SSH public key below."
echo "This typically starts with 'ssh-rsa', 'ssh-ed25519', or 'ecdsa-sha2'."
echo "You can usually find it in ~/.ssh/id_rsa.pub or ~/.ssh/id_ed25519.pub on your local machine."
echo ""
read -p "SSH Public Key: " YOUR_SSH_PUBLIC_KEY

# Validate SSH key format
if [[ -z "$YOUR_SSH_PUBLIC_KEY" ]]; then
    print_error "No SSH key provided. Setup cannot continue without an SSH key."
    exit 1
fi

if [[ ! "$YOUR_SSH_PUBLIC_KEY" =~ ^(ssh-ed25519|ecdsa-sha2|ssh-rsa) ]]; then
    print_error "Invalid SSH key format. Key should start with ssh-ed25519, ecdsa-sha2, or ssh-rsa"
    exit 1
fi

# Optional: nudge users away from RSA to ed25519
if [[ "$YOUR_SSH_PUBLIC_KEY" =~ ^ssh-rsa ]]; then
    print_warning "RSA keys are accepted, but ssh-ed25519 is recommended for new keys."
fi

# Optional: Ask for custom SSH port
echo ""
read -p "Enter SSH port (default 22, recommended to change for security): " CUSTOM_SSH_PORT
if [[ ! -z "$CUSTOM_SSH_PORT" ]] && [[ "$CUSTOM_SSH_PORT" =~ ^[0-9]+$ ]] && [ "$CUSTOM_SSH_PORT" -ge 1 ] && [ "$CUSTOM_SSH_PORT" -le 65535 ]; then
    SSH_PORT="$CUSTOM_SSH_PORT"
fi

# Optional: Ask for custom username
echo ""
read -p "Enter deploy username (default 'deploy'): " CUSTOM_DEPLOY_USER
if [[ ! -z "$CUSTOM_DEPLOY_USER" ]] && [[ "$CUSTOM_DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    DEPLOY_USER="$CUSTOM_DEPLOY_USER"
fi

# Prompt for deploy user password
echo ""
while true; do
    read -s -p "Enter password for $DEPLOY_USER user: " DEPLOY_PASSWORD
    echo
    read -s -p "Confirm password: " DEPLOY_PASSWORD_CONFIRM
    echo
    
    if [[ "$DEPLOY_PASSWORD" == "$DEPLOY_PASSWORD_CONFIRM" ]]; then
        if [[ ${#DEPLOY_PASSWORD} -lt 8 ]]; then
            print_warning "Password must be at least 8 characters long. Please try again."
        else
            break
        fi
    else
        print_warning "Passwords do not match. Please try again."
    fi
done

echo ""
print_status "Configuration Summary:"
echo "  Deploy User: $DEPLOY_USER"
echo "  SSH Port: $SSH_PORT"
echo "  SSH Key: ${YOUR_SSH_PUBLIC_KEY:0:50}..."
echo "  Password: [set by user]"
echo ""
read -p "Continue with setup? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_warning "Setup cancelled"
    exit 1
fi

print_status "Starting Hetzner VPS setup for Kamal deployment..."

# Update system
print_status "Updating system packages..."
retry 3 5 apt-get -o Acquire::Retries=3 -o Dpkg::Lock::Timeout=120 update
retry 2 10 apt-get -o Acquire::Retries=3 -o Dpkg::Lock::Timeout=120 upgrade -y
retry 2 10 apt-get -o Acquire::Retries=3 -o Dpkg::Lock::Timeout=120 dist-upgrade -y
apt-get autoremove -y

# Install essential packages
print_status "Installing essential packages..."
retry 3 5 apt-get -o Acquire::Retries=3 -o Dpkg::Lock::Timeout=120 install -y \
    curl \
    wget \
    vim \
    htop \
    git \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    make \
    build-essential \
    net-tools \
    rsync

# Configure automatic security updates
print_status "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Create deploy user
print_status "Creating deploy user..."
if ! id "$DEPLOY_USER" &>/dev/null; then
    useradd -m -s /bin/bash $DEPLOY_USER
    echo "$DEPLOY_USER:$DEPLOY_PASSWORD" | chpasswd

    # Set up SSH key for deploy user
    mkdir -p /home/$DEPLOY_USER/.ssh
    echo "$YOUR_SSH_PUBLIC_KEY" > /home/$DEPLOY_USER/.ssh/authorized_keys
    chmod 700 /home/$DEPLOY_USER/.ssh
    chmod 600 /home/$DEPLOY_USER/.ssh/authorized_keys
    chown -R $DEPLOY_USER:$DEPLOY_USER /home/$DEPLOY_USER/.ssh
else
    print_warning "Deploy user already exists, skipping..."
fi

# Configure sudoers for deploy user (full sudo access with password)
print_status "Configuring sudo access..."
cat > /etc/sudoers.d/deploy << EOF
# Allow deploy user to use sudo with password for all commands
$DEPLOY_USER ALL=(ALL:ALL) ALL
EOF
chmod 0440 /etc/sudoers.d/deploy

# Validate sudoers file to avoid locking out sudo
if ! /usr/sbin/visudo -cf /etc/sudoers.d/deploy >/dev/null; then
    print_error "Invalid sudoers configuration for deploy user. Reverting."
    rm -f /etc/sudoers.d/deploy
    exit 1
fi

# Harden SSH configuration
print_status "Hardening SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# SSH Hardening Configuration
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
MaxAuthTries 3
MaxSessions 10
MaxStartups 10:30:60
LoginGraceTime 60
StrictModes yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
IgnoreRhosts yes
HostbasedAuthentication no
AllowUsers $DEPLOY_USER
EOF

# Install Docker
print_status "Installing Docker..."

# Install Docker APT GPG key (make sure apt can read it)
DOCKER_KEYRING="/etc/apt/keyrings/docker.gpg"
TMP_DOCKER_GPG="/tmp/docker-ubuntu-apt.gpg"

install -m 0755 -d /etc/apt/keyrings
retry 3 3 curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$TMP_DOCKER_GPG"
gpg --batch --yes --dearmor -o "$DOCKER_KEYRING" "$TMP_DOCKER_GPG"
rm -f "$TMP_DOCKER_GPG"
chmod a+r "$DOCKER_KEYRING"

# Log the fingerprint of the installed keyring for auditability
DOCKER_GPG_FINGERPRINT_ACTUAL=$(gpg --show-keys --with-colons "$DOCKER_KEYRING" | awk -F: '/^fpr:/ {print toupper($10); exit}')
print_status "Docker APT key fingerprint: ${DOCKER_GPG_FINGERPRINT_ACTUAL:-unknown}"

echo "deb [arch=$(dpkg --print-architecture) signed-by=$DOCKER_KEYRING] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
retry 3 5 apt-get -o Acquire::Retries=3 -o Dpkg::Lock::Timeout=120 update
retry 3 5 apt-get -o Acquire::Retries=3 -o Dpkg::Lock::Timeout=120 install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add deploy user to docker group
usermod -aG docker $DEPLOY_USER

# Configure Docker daemon for security
print_status "Configuring Docker daemon..."
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'EOF'
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true
}
EOF

systemctl restart docker
systemctl enable docker

# Configure fail2ban
print_status "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[docker]
enabled = true
filter = docker
logpath = /var/lib/docker/containers/*/*-json.log
maxretry = 5
bantime = 3600
EOF

# Create Docker fail2ban filter
cat > /etc/fail2ban/filter.d/docker.conf << 'EOF'
[Definition]
failregex = ^.*authentication failure.*remote_addr=<HOST>.*$
            ^.*401 Unauthorized.*remote_addr=<HOST>.*$
ignoreregex =
EOF

systemctl restart fail2ban
systemctl enable fail2ban

# Set up kernel security parameters
print_status "Configuring kernel security parameters..."
cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Time-wait assassination hazards protection
net.ipv4.tcp_rfc1337 = 1

# Decrease the time default value for tcp_fin_timeout
net.ipv4.tcp_fin_timeout = 15

# Decrease the time default value for tcp_keepalive_time
net.ipv4.tcp_keepalive_time = 300

# IP Forwarding (needed for Docker)
net.ipv4.ip_forward = 1

# Increase system file descriptor limit
fs.file-max = 65535

# Increase ephemeral IP ports
net.ipv4.ip_local_port_range = 10000 65000

# Enable BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p /etc/sysctl.d/99-security.conf

# Configure swap file based on system RAM
print_status "Configuring swap space..."
setup_swap() {
    # Check if swap already exists
    if swapon --show | grep -q '/swapfile'; then
        print_warning "Swap file already exists, skipping..."
        return 0
    fi
    
    # Get total RAM in MB
    TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    
    # Get available disk space in MB (excluding reserved blocks)
    AVAILABLE_DISK_MB=$(df -BM / | awk 'NR==2 {print int($4)}')
    
    # Calculate 10% of available disk space as maximum swap size
    MAX_SWAP_FROM_DISK=$((AVAILABLE_DISK_MB / 10))
    
    # Determine ideal swap size based on RAM
    if [ "$TOTAL_RAM_MB" -le 2048 ]; then
        # 2GB or less: 2x RAM
        IDEAL_SWAP_MB=$((TOTAL_RAM_MB * 2))
    elif [ "$TOTAL_RAM_MB" -le 4096 ]; then
        # 2-4GB: Equal to RAM
        IDEAL_SWAP_MB=$TOTAL_RAM_MB
    elif [ "$TOTAL_RAM_MB" -le 8192 ]; then
        # 4-8GB: 4GB swap
        IDEAL_SWAP_MB=4096
    else
        # 8GB+: 4GB swap (can be adjusted based on needs)
        IDEAL_SWAP_MB=4096
    fi
    
    # Use the smaller of ideal swap or 10% of available disk
    if [ "$IDEAL_SWAP_MB" -gt "$MAX_SWAP_FROM_DISK" ]; then
        SWAP_SIZE_MB=$MAX_SWAP_FROM_DISK
        print_warning "Limited swap to ${SWAP_SIZE_MB}MB (10% of ${AVAILABLE_DISK_MB}MB available disk)"
    else
        SWAP_SIZE_MB=$IDEAL_SWAP_MB
    fi
    
    # Ensure minimum viable swap (at least 512MB) or skip if not enough space
    if [ "$SWAP_SIZE_MB" -lt 512 ]; then
        print_warning "Insufficient disk space for swap (need at least 512MB, have ${SWAP_SIZE_MB}MB available)"
        print_warning "Skipping swap creation - system will run without swap"
        return 0
    fi
    
    print_status "Creating ${SWAP_SIZE_MB}MB swap file (System RAM: ${TOTAL_RAM_MB}MB, Available disk: ${AVAILABLE_DISK_MB}MB)..."
    
    # Create swap file - try fallocate first, fall back to dd
    if ! fallocate -l ${SWAP_SIZE_MB}M /swapfile 2>/dev/null; then
        print_warning "fallocate failed, using dd instead (this may take longer)..."
        if ! dd if=/dev/zero of=/swapfile bs=1M count=$SWAP_SIZE_MB status=progress 2>/dev/null; then
            print_error "Failed to create swap file - insufficient disk space"
            rm -f /swapfile 2>/dev/null
            return 1
        fi
    fi
    
    # Set correct permissions
    chmod 600 /swapfile
    
    # Make it a swap file
    mkswap /swapfile
    
    # Enable the swap file
    swapon /swapfile
    
    # Make swap permanent
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    # Configure swappiness (10 is good for servers, reduces swap usage)
    echo 'vm.swappiness=10' >> /etc/sysctl.d/99-swap.conf
    echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.d/99-swap.conf
    sysctl -p /etc/sysctl.d/99-swap.conf
    
    print_status "Swap configuration complete"
}

# Run swap setup
setup_swap

# Set up log rotation for Docker containers
print_status "Configuring Docker log rotation..."
cat > /etc/logrotate.d/docker << 'EOF'
/var/lib/docker/containers/*/*.log {
    daily
    rotate 7
    compress
    missingok
    delaycompress
    copytruncate
}
EOF

# Create directory for Kamal and app data
print_status "Creating directories for deployment..."
mkdir -p /home/$DEPLOY_USER/apps
chown -R $DEPLOY_USER:$DEPLOY_USER /home/$DEPLOY_USER/apps

# Set up basic monitoring
print_status "Setting up basic monitoring..."
cat > /usr/local/bin/server-health-check.sh << 'EOF'
#!/bin/bash
# Basic health check script
THRESHOLD=80
DISK_USAGE=$(df / | grep / | awk '{ print $5 }' | sed 's/%//g')
MEM_USAGE=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print int(100 - $1)}')

if [ "$DISK_USAGE" -gt "$THRESHOLD" ]; then
    echo "Warning: Disk usage is at ${DISK_USAGE}%"
fi

if [ "$MEM_USAGE" -gt "$THRESHOLD" ]; then
    echo "Warning: Memory usage is at ${MEM_USAGE}%"
fi

if [ "$CPU_USAGE" -gt "$THRESHOLD" ]; then
    echo "Warning: CPU usage is at ${CPU_USAGE}%"
fi
EOF

chmod +x /usr/local/bin/server-health-check.sh

# Add health check to crontab for root user
(crontab -l 2>/dev/null || true; echo "0 */6 * * * /usr/local/bin/server-health-check.sh") | crontab -u root -

# Install and configure chrony for time synchronization
print_status "Configuring time synchronization..."
retry 3 5 apt-get -o Acquire::Retries=3 -o Dpkg::Lock::Timeout=120 install -y chrony
systemctl enable chrony
systemctl start chrony

# Create a summary file
print_status "Creating setup summary..."
cat > /root/server-setup-summary.txt << EOF
==============================================
SERVER SETUP COMPLETE - SAVE THIS INFORMATION
==============================================

Deploy User: $DEPLOY_USER
Deploy Password: [Password set during installation]
SSH Port: $SSH_PORT

IMPORTANT NEXT STEPS:
1. Test SSH access: ssh -p $SSH_PORT $DEPLOY_USER@$(curl -s ifconfig.me)
2. Once confirmed working, you can now use 'sudo su -' to switch to root
3. Configure your domain's DNS to point to this server
4. Update Kamal's deploy.yml with this server's IP
5. Configure Hetzner Cloud Firewall to allow ports 22 (or $SSH_PORT), 80, and 443

SECURITY FEATURES ENABLED:
- Fail2ban (SSH and Docker protection)
- Automatic security updates
- SSH hardening (no root, key-only auth)
- Docker with security options
- Kernel security parameters
- Log rotation

MONITORING:
- Basic health checks every 6 hours
- Check logs: journalctl -xe
- Check fail2ban: fail2ban-client status

==============================================
EOF

print_status "Setup complete! Summary saved to /root/server-setup-summary.txt"
print_warning "IMPORTANT: Test SSH access with deploy user before closing this session!"
print_warning "SSH Command: ssh -p $SSH_PORT $DEPLOY_USER@$(curl -s ifconfig.me)"

# Prompt to verify SSH access before restarting service to avoid lockout
echo ""
print_status "Verify SSH access with the deploy user before restarting SSH."
echo "Open a new terminal and test: ssh -p $SSH_PORT $DEPLOY_USER@$(curl -s ifconfig.me)"
read -p "SSH connection tested and working? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Restarting SSH service..."
    systemctl restart ssh
else
    print_warning "Skipped SSH restart. SSH hardening changes will not take effect until you restart SSH manually (systemctl restart ssh)."
fi

echo ""
print_status "Running system verification..."
echo ""

# Verification function
verify_service() {
    local service=$1
    local display_name=$2
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}✓${NC} $display_name is running"
    else
        echo -e "${RED}✗${NC} $display_name is not running"
    fi
}

# Verify all services
echo "=== Service Status ==="
verify_service "docker" "Docker"
verify_service "ssh" "SSH"
verify_service "fail2ban" "Fail2ban"
verify_service "unattended-upgrades" "Automatic Updates"
verify_service "chrony" "Time Sync (Chrony)"

echo ""
echo "=== System Checks ==="

# Check Docker
if docker run --rm hello-world &>/dev/null; then
    echo -e "${GREEN}✓${NC} Docker can run containers"
else
    echo -e "${RED}✗${NC} Docker container test failed"
fi

# Check deploy user
if id "$DEPLOY_USER" &>/dev/null; then
    echo -e "${GREEN}✓${NC} Deploy user '$DEPLOY_USER' exists"
    if groups $DEPLOY_USER | grep -q docker; then
        echo -e "${GREEN}✓${NC} Deploy user is in docker group"
    else
        echo -e "${RED}✗${NC} Deploy user is not in docker group"
    fi
else
    echo -e "${RED}✗${NC} Deploy user does not exist"
fi

# Check SSH configuration
if [ -f /home/$DEPLOY_USER/.ssh/authorized_keys ]; then
    echo -e "${GREEN}✓${NC} SSH key configured for deploy user"
else
    echo -e "${RED}✗${NC} SSH key not found for deploy user"
fi

# Check fail2ban jails
if fail2ban-client status | grep -q "ssh"; then
    echo -e "${GREEN}✓${NC} Fail2ban SSH jail is active"
else
    echo -e "${YELLOW}⚠${NC} Fail2ban SSH jail not detected"
fi

# Check kernel security parameters
if [ "$(sysctl -n net.ipv4.tcp_syncookies)" = "1" ]; then
    echo -e "${GREEN}✓${NC} SYN flood protection enabled"
else
    echo -e "${RED}✗${NC} SYN flood protection not enabled"
fi

if [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ]; then
    echo -e "${GREEN}✓${NC} IP forwarding enabled (required for Docker)"
else
    echo -e "${RED}✗${NC} IP forwarding not enabled"
fi

if [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ]; then
    echo -e "${GREEN}✓${NC} BBR congestion control enabled"
else
    echo -e "${YELLOW}⚠${NC} BBR congestion control not enabled"
fi

# Check unattended upgrades configuration
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ] && [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    echo -e "${GREEN}✓${NC} Automatic security updates configured"
else
    echo -e "${RED}✗${NC} Automatic updates not configured"
fi

# Check health monitoring script
if [ -f /usr/local/bin/server-health-check.sh ]; then
    echo -e "${GREEN}✓${NC} Health monitoring script installed"
else
    echo -e "${YELLOW}⚠${NC} Health monitoring script not found"
fi

# Check system resources
echo ""
echo "=== System Resources ==="
echo "Memory: $(free -h | awk '/^Mem:/ {print $3 " / " $2 " used"}')"
echo "Disk: $(df -h / | awk 'NR==2 {print $3 " / " $2 " used (" $5 ")"}')"
echo "Load: $(uptime | awk -F'load average:' '{print $2}')"

# Count any failed services
FAILED_SERVICES=$(systemctl --failed --no-legend | wc -l)
if [ "$FAILED_SERVICES" -eq 0 ]; then
    echo -e "${GREEN}✓${NC} No failed system services"
else
    echo -e "${YELLOW}⚠${NC} $FAILED_SERVICES failed system services detected"
    echo "  Run 'systemctl --failed' to see details"
fi

echo ""
print_status "Server preparation complete! Your server is ready for Kamal deployment."
