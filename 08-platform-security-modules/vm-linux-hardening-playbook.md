# 🖥️ Virtual Machine (VM) & Linux Server Hardening Playbook

> **Author**: Kaizo  
> **Target OS**: Ubuntu 22.04 / 24.04 LTS, Debian 12, Rocky/RHEL 9 (AWS EC2, DigitalOcean, GCP Compute, Linode, Azure VM)  
> **Key Mitigations**: `CWE-284` (Improper Access Control), `CWE-16` (Configuration Flaws), `CWE-250` (Execution with Unnecessary Privileges)

---

## 🔒 1. VM Defense-in-Depth Architecture

```
[Public Internet]
       │
       ▼ (Port 22 SSH Blocked / Gated by Fail2ban & Public Key ONLY)
[Host Firewall: UFW / iptables] ──(Port 80/443 Only)──> [Reverse Proxy: Nginx / Caddy]
       │                                                          │
       ▼                                                          ▼
[Kernel Hardening / sysctl]                                [Docker Daemon (Rootless)]
       │                                                          │
       ▼                                                          ▼
[Automated Security Patches]                               [App Container (Non-root UID 1001)]
```

---

## 🛡️ 2. SSH Daemon Hardening (`/etc/ssh/sshd_config.d/99-hardened.conf`)

> [!IMPORTANT]
> Never allow root login over SSH or password authentication. Always use Ed25519 or RSA-4096 key pairs.

```ini
# /etc/ssh/sshd_config.d/99-hardened.conf
Port 2222                          # Change default port to reduce brute-force bot noise
PermitRootLogin no                 # Never allow direct root login
PasswordAuthentication no          # Mandate SSH Key authentication
PubkeyAuthentication yes
MaxAuthTries 3                     # Disconnect after 3 failed attempts
ClientAliveInterval 300            # Drop idle sessions after 15 mins
ClientAliveCountMax 3
X11Forwarding no                   # Disable unused features
AllowTcpForwarding yes             # Keep for secure bastion tunneling
```

---

## 🧱 3. Host Firewall & Brute-Force Protection (UFW & Fail2ban)

### UFW Setup:
```bash
# 1. Reset and set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 2. Allow SSH on custom port (e.g. 2222)
sudo ufw allow 2222/tcp comment 'Hardened SSH'

# 3. Allow HTTP & HTTPS
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'

# 4. NEVER ALLOW DATABASE PORTS (5432, 3306, 27017, 6379) EXTERNALLY!

# 5. Enable firewall
sudo ufw enable
```

### Fail2ban Configuration (`/etc/fail2ban/jail.local`):
```ini
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = 2222
mode = aggressive
```

---

## ⚙️ 4. Kernel Network Hardening (`/etc/sysctl.d/99-security.conf`)

Mitigate SYN floods, IP spoofing, packet redirects, and man-in-the-middle attacks at the Linux kernel level:

```ini
# Disable IP packet forwarding (unless configured as a VPN router)
net.ipv4.ip_forward = 0

# Prevent IP Spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP Echo Broadcasts (Smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable ICMP redirect acceptance (MITM protection)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Enable TCP SYN Cookies (SYN Flood DoS mitigation)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
```

Apply with: `sudo sysctl --system`

---

## 🔄 5. Automated Security Patching (`unattended-upgrades`)

Ensure the OS automatically downloads and applies security patches without developer intervention:

```bash
sudo apt update && sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## 🐳 6. Docker Daemon Hardening on VMs

1. **Disable Inter-Container Communication (ICC)** if not required:
   ```json
   // /etc/docker/daemon.json
   {
     "icc": false,
     "no-new-privileges": true,
     "live-restore": true,
     "userland-proxy": false,
     "log-driver": "json-file",
     "log-opts": {
       "max-size": "10m",
       "max-file": "3"
     }
   }
   ```
2. **Never expose the Docker socket (`/var/run/docker.sock`)** to untrusted containers or network ports.
