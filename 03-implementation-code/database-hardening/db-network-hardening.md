# 🗄️ Database Network Isolation & Hardening Guide

> **Mitigates**: `CWE-284` (Public Exposure of Relational Database Daemon)  
> **Target Databases**: PostgreSQL, MySQL / MariaDB, MongoDB, Redis

---

## 🔒 The Zero-Public-Exposure Principle

```
[Public Internet] 
       │ 
       ▼ (Port 443 / HTTPS ONLY)
[Cloudflare / Nginx Reverse Proxy]
       │ 
       ▼ (Private VPC Subnet / 127.0.0.1)
[Backend Application Server]
       │ 
       ▼ (Private Internal Subnet ONLY)
[Database Daemon (5432 / 3306 / 27017)] ◄───❌ BLOCKED from Public Internet!
```

---

## 1. PostgreSQL Hardening

### Configuration (`/etc/postgresql/<version>/main/postgresql.conf`)
```ini
# Listen ONLY on localhost and/or private VPC subnet IP
listen_addresses = 'localhost,10.0.2.15'
port = 5432
max_connections = 100

# Require password encryption with SCRAM-SHA-256
password_encryption = scram-sha-256

# Force SSL / TLS for all incoming connections
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
```

### Client Authentication (`/etc/postgresql/<version>/main/pg_hba.conf`)
```ini
# TYPE  DATABASE        USER            ADDRESS                 METHOD
# Local socket connections
local   all             postgres                                peer

# IPv4 local connections (App server on same host)
host    all             kaizo_app       127.0.0.1/32            scram-sha-256

# IPv4 internal VPC subnet (App server on separate private VM)
hostssl all             kaizo_app       10.0.1.0/24             scram-sha-256

# Reject everything else explicitly
host    all             all             0.0.0.0/0               reject
```

---

## 2. MySQL / MariaDB Hardening

### Configuration (`/etc/mysql/mysql.conf.d/mysqld.cnf`)
```ini
[mysqld]
# Bind strictly to local loopback or private interface
bind-address            = 127.0.0.1
mysqlx-bind-address     = 127.0.0.1

# Disable symbolic links to prevent table overwrite attacks
symbolic-links          = 0

# Enforce secure transport
require_secure_transport = ON
```

### User Permissions (Least Privilege):
```sql
-- Never use root@'%'
CREATE USER 'kaizo_app'@'127.0.0.1' IDENTIFIED BY 'STRONG_SECRET_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON kaizo_production.* TO 'kaizo_app'@'127.0.0.1';
FLUSH PRIVILEGES;
```

---

## 3. MongoDB Hardening

### Configuration (`/etc/mongod.conf`)
```yaml
net:
  port: 27017
  bindIp: 127.0.0.1 # NEVER 0.0.0.0

security:
  authorization: enabled # Require authentication for all DB operations
```

---

## 4. Redis Hardening

### Configuration (`/etc/redis/redis.conf`)
```ini
bind 127.0.0.1 ::1
protected-mode yes
port 6379
requirepass YOUR_COMPLEX_LONG_REDIS_PASSWORD
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
```

---

## 5. Host-Level Firewall (Linux UFW / iptables)

```bash
# Enable UFW
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow Web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow SSH only from specific IP/VPN
sudo ufw allow from 203.0.113.50 to any port 22 proto tcp

# Verify database ports are NOT in UFW allow list:
sudo ufw status verbose
```
