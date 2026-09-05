#!/usr/bin/env bash
# ==============================================================================
# Kaizo DevSec Framework - Automated VM & Linux Server Hardening Script
# Target: Ubuntu 22.04 / 24.04 LTS / Debian 12
# Run as root: sudo bash vm-hardening-script.sh
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo "🛡️ Kaizo DevSec: Automated Linux VM Hardening"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run as root (sudo)."
  exit 1
fi

# 1. Update OS packages
echo "📦 Step 1: Updating system packages..."
apt-get update -y && apt-get upgrade -y

# 2. Install essential security tools
echo "🔧 Step 2: Installing security tools (UFW, Fail2ban, Unattended-Upgrades)..."
apt-get install -y ufw fail2ban unattended-upgrades libpam-tmpdir curl git

# 3. Configure automated security updates
echo "🔄 Step 3: Enabling unattended security upgrades..."
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades

# 4. Kernel sysctl network hardening
echo "⚙️ Step 4: Applying kernel sysctl hardening..."
cat << 'EOF' > /etc/sysctl.d/99-kaizo-security.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
EOF
sysctl --system > /dev/null

# 5. Configure Firewall (UFW)
echo "🧱 Step 5: Configuring UFW firewall rules..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable

# 6. Configure Fail2ban
echo "🚨 Step 6: Enabling Fail2ban for brute-force protection..."
systemctl enable fail2ban
systemctl restart fail2ban

echo "=========================================================="
echo "✅ VM Hardening Completed Successfully!"
echo "   - Firewall Active: Ports 22, 80, 443 only"
echo "   - Fail2ban: Active"
echo "   - Kernel Hardening: Applied"
echo "   - Unattended Upgrades: Enabled"
echo "=========================================================="
