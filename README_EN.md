<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="Pulse Logo">
</p>

<h1 align="center">Pulse</h1>

<p align="center">
  <b>Lightweight Server Monitoring System</b><br>
  Real-time monitoring of CPU, memory, disk, network and other metrics
</p>

<p align="center">
  <a href="README_EN.md">English</a> | <a href="README.md">中文</a>
</p>

<p align="center">
  <a href="https://github.com/xhhcn/Pulse/releases"><img src="https://img.shields.io/github/v/release/xhhcn/Pulse?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://hub.docker.com/r/xhh1128/pulse"><img src="https://img.shields.io/docker/pulls/xhh1128/pulse?style=flat-square&color=blue" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/xhh1128/pulse"><img src="https://img.shields.io/docker/image-size/xhh1128/pulse/latest?style=flat-square&color=blue" alt="Docker Size"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/xhhcn/Pulse?style=flat-square&color=green" alt="License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Astro-4.0+-FF5D01?style=flat-square&logo=astro&logoColor=white" alt="Astro">
  <img src="https://img.shields.io/badge/Platform-amd64%20%7C%20arm64-lightgrey?style=flat-square" alt="Platform">
</p>

---

<p align="center">
  Sponsored by <a href="https://www.dooki.cloud" target="_blank"><b>DokiDoki CDN</b></a><br><br>
  <a href="https://www.dooki.cloud" target="_blank">
    <img src="assets/doki.png" height="60" alt="DokiDoki CDN">
  </a>
</p>

---

## ✨ What's New in v1.3.0

- 🔐 **Shared Secret Authentication** - All clients use a unified shared secret to connect to the server, simplifying deployment
- 🏷️ **Special Tag Support** - New `traffic:in/out` and `speed:in/out` tags for real-time traffic statistics and network speed display
- 🎨 **Custom CSS/JS** - Support for site-wide custom styles and scripts to create a personalized monitoring dashboard

---

## 🚀 Server Installation

### Method 1: Standalone Binary Deployment (Recommended for VPS)

#### One-line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/install-pulse-server.sh | sudo bash
```

The script will automatically:
- ✅ Detect system architecture
- ✅ Download the appropriate binary
- ✅ Configure systemd service
- ✅ Start service and enable auto-start

#### Update Server

**amd64:**
```bash
sudo systemctl stop pulse-server && sudo wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-amd64 -O /opt/pulse/pulse-server && sudo chmod +x /opt/pulse/pulse-server && sudo systemctl start pulse-server
```

**arm64:**
```bash
sudo systemctl stop pulse-server && sudo wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-arm64 -O /opt/pulse/pulse-server && sudo chmod +x /opt/pulse/pulse-server && sudo systemctl start pulse-server
```

#### Uninstall Server

**Remove program only (keep data):**
```bash
sudo systemctl stop pulse-server && sudo systemctl disable pulse-server && sudo rm -f /etc/systemd/system/pulse-server.service /opt/pulse/pulse-server && sudo systemctl daemon-reload
```

**Complete removal (including data):**
```bash
sudo systemctl stop pulse-server && sudo systemctl disable pulse-server && sudo rm -f /etc/systemd/system/pulse-server.service && sudo rm -rf /opt/pulse && sudo systemctl daemon-reload
```

#### Manual Installation

**Linux (amd64)**
```bash
# Download
wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-amd64
chmod +x pulse-server-standalone-linux-amd64

# Run
./pulse-server-standalone-linux-amd64
```

**Linux (arm64)**
```bash
# Download
wget https://github.com/xhhcn/Pulse/releases/latest/download/pulse-server-standalone-linux-arm64
chmod +x pulse-server-standalone-linux-arm64

# Run
./pulse-server-standalone-linux-arm64
```

Access `http://YOUR_IP:8008` to view the monitoring dashboard

---

### Method 2: Docker Deployment (Recommended for Production)

[![Docker](https://img.shields.io/badge/Docker-xhh1128/pulse-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/r/xhh1128/pulse)

#### Docker Compose

```bash
mkdir pulse && cd pulse
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/docker-compose.yaml -o docker-compose.yaml
docker compose up -d
```

> **IPv6 Support**: If your server requires IPv6 support, please refer to the [Docker IPv6 Configuration](#docker-ipv6-configuration) section below.

#### Docker Run

```bash
docker run -d \
  --name pulse-monitor \
  -p 8008:8008 \
  -v $(pwd)/pulse-data:/app/data \
  --restart unless-stopped \
  xhh1128/pulse:latest
```

Access `http://YOUR_IP:8008` to view the monitoring dashboard

---

## 🌐 Docker IPv6 Configuration

Pulse supports IPv4/IPv6 dual-stack. If your server requires IPv6 support, please follow these steps:

### Prerequisites

1. **Ensure the host has IPv6 enabled**
   ```bash
   # Check if IPv6 is enabled
   ip -6 addr show
   
   # Check if IPv6 forwarding is enabled
   sysctl net.ipv6.conf.all.forwarding
   # If output is 0, enable it:
   sudo sysctl -w net.ipv6.conf.all.forwarding=1
   
   # Enable permanently (edit /etc/sysctl.conf)
   echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
   ```

2. **Configure Docker Daemon to enable IPv6**

   Edit or create `/etc/docker/daemon.json`:
   ```json
   {
     "ipv6": true,
     "fixed-cidr-v6": "fd00:dead:beef:c0::/80",
     "experimental": true,
     "ip6tables": true
   }
   ```
   
   > **Note**:
   > - `ipv6: true` - Globally enable Docker's IPv6 support (**required**)
   > - `fixed-cidr-v6` - IPv6 subnet range used by Docker (adjust according to your actual situation)
   > - `experimental: true` - Enable experimental features (required for some IPv6 features)
   > - `ip6tables: true` - Enable IPv6 iptables support (for network isolation and port mapping)
   
   Restart Docker service to apply the configuration:
   ```bash
   sudo systemctl restart docker
   ```

3. **Configure docker-compose.yaml to enable IPv6**

   Configure the network to enable IPv6 in `docker-compose.yaml`:
   ```yaml
   services:
     pulse:
       image: xhh1128/pulse:latest
       container_name: pulse-monitor
       ports:
         - 8008:8008
       volumes:
         - pulse-data:/app/data
       restart: unless-stopped
       networks:
         - pulse-network

   volumes:
     pulse-data:

   networks:
     pulse-network:
       enable_ipv6: true
       ipam:
         driver: default
   ```

4. **Recreate containers**

   ```bash
   docker compose down
   docker compose up -d
   ```

5. **Verify IPv6 configuration**

   ```bash
   # Check container IPv6 address
   docker exec pulse-monitor ip -6 addr show
   
   # Test IPv6 connectivity (if container has ping6)
   docker exec pulse-monitor ping6 -c 2 2001:4860:4860::8888
   ```

---

## 📦 Client Installation

### Linux

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- \
  --id <ID> --server <SERVER_URL> --secret <SECRET>
```

### macOS (Intel / Apple Silicon)

The install script auto-detects CPU architecture and registers the service as a `launchd` daemon (auto-starts on boot):

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- \
  --id <ID> --server <SERVER_URL> --secret <SECRET>
```

> **Note**: macOS requires `sudo` to write `.plist` files into `/Library/LaunchDaemons/`.

**macOS service management commands:**

```bash
# Check status
sudo launchctl print system/com.pulse.client

# View logs
tail -f /var/log/pulse-client.log

# Restart service (recommended)
sudo launchctl kickstart -k system/com.pulse.client

# Stop service
sudo launchctl bootout system/com.pulse.client

# Start a stopped service again
sudo launchctl bootstrap system /Library/LaunchDaemons/com.pulse.client.plist
```

### Windows (Administrator PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -Command "& { $env:AgentId='<ID>'; $env:ServerBase='<SERVER_URL>'; $env:Secret='<SECRET>'; irm https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.ps1 | iex }"
```

| Parameter | Description |
|------|------|
| `<ID>` | Unique server identifier (set when adding system in admin panel) |
| `<SERVER_URL>` | Server URL, e.g., `http://your-server:8008` |
| `<SECRET>` | Authentication secret (auto-generated after adding system in admin panel, viewable in system details) |

> **Note**: The `--secret` parameter is optional. If the server system is configured with a secret, you must provide the correct secret to register successfully.

### Uninstall Client

**Linux:**
```bash
sudo systemctl stop pulse-client && sudo systemctl disable pulse-client && sudo rm -f /opt/pulse/probe-client /etc/systemd/system/pulse-client.service && sudo systemctl daemon-reload
```

**macOS (with auto-update):**
```bash
sudo launchctl bootout system/com.pulse.client 2>/dev/null || true
sudo launchctl bootout system/com.pulse.client.update 2>/dev/null || true
sudo rm -rf /opt/pulse \
  /Library/LaunchDaemons/com.pulse.client.plist \
  /Library/LaunchDaemons/com.pulse.client.update.plist
```

**Windows (Administrator PowerShell):**
```powershell
Stop-ScheduledTask -TaskName 'PulseClient' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'PulseClient' -Confirm:$false -ErrorAction SilentlyContinue; Remove-NetFirewallRule -DisplayName 'Pulse Monitoring Client*' -ErrorAction SilentlyContinue; Remove-Item -Path "$env:ProgramFiles\Pulse" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## ⚙️ Usage

1. Access `http://YOUR_IP:8008/admin` to enter the admin panel
2. Set admin password on first visit
3. Click **Add System** to add a server
4. After adding a system, a **Secret** (authentication key) will be automatically generated
5. Run the client installation command on the target machine, **must include the correct Secret**
6. Data is automatically reported and displayed in real-time

> **Tip**: In the admin panel's system list, click the copy button on the right side of the system to quickly copy the installation command with Secret.

---

## 📊 Monitoring Metrics

| Metric | Content |
|------|------|
| **CPU** | Usage, cores, model |
| **Memory** | Usage, total |
| **Disk** | Usage, total |
| **Network** | Upload/download speed, TCPing latency |
| **System** | Uptime, IP, location |

---

## 🚚 Migrating to Another Server

All of Pulse's server state (registered systems, shared secrets, TCPing history, admin password, dashboard config, …) lives in **one bbolt file**. The repo ships `scripts/migrate.sh`, which wraps the entire migration into **a single command** — run it on the new server and it pulls everything across from the old one. **The old server stays fully online** the whole time, with zero data loss.

> Every client keeps its `AGENT_ID` / `SECRET`; the only thing that might need updating is `SERVER_BASE` (the URL).  
> If the old host sits behind a domain + reverse proxy, flip DNS to the new IP and clients need no change at all.

### ✨ One command end-to-end

```bash
# ── On the NEW server ──

# 1) Install Pulse (pick one)
#    A. Standalone binary (systemd) — recommended, lowest overhead
#       The installer also drops backup/restore/migrate into /opt/pulse/scripts/
#       and creates the pulse-migrate / pulse-backup / pulse-restore commands.
curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/install-pulse-server.sh | sudo bash

#    B. Docker Compose
# mkdir pulse && cd pulse && \
# curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/docker-compose.yaml -o docker-compose.yaml && \
# docker compose up -d && \
# curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse/main/scripts/migrate.sh -o migrate.sh && chmod +x migrate.sh
#       migrate.sh will auto-fetch its backup.sh/restore.sh siblings from the repo — one file is enough.

# 2) One command — prompts for the OLD admin password (never shown on screen)
sudo pulse-migrate --from https://OLD_HOST                 # binary install (simplest)
# or, in the Docker directory:
# sudo ./migrate.sh --from https://OLD_HOST

# Non-interactive (CI / automation — use an env var, not an argv flag):
# sudo PASSWORD='OldAdminPW' pulse-migrate --from https://OLD_HOST -y
```

`migrate.sh` performs, in order:

1. Log in to the **old server** with the password you supplied and exchange it for a one-shot admin token. The password is piped to `curl` via stdin, so it never shows up in `ps`.
2. Call `GET /api/admin/backup` to pull a **transactionally-consistent** hot snapshot — built on bbolt's `Tx.WriteTo` inside a read-only transaction, so it can never capture a half-written page. **The old server is never stopped.**
3. Validate the downloaded file (size + bbolt magic number `0xEDDA0CED`) so a truncated `scp` or a still-gzipped archive is caught *before* anything destructive runs.
4. Auto-detect whether the new server runs under **Docker Compose** or **systemd (standalone binary)**, stop it, save the current `metrics.db` as `metrics.db.pre-restore-<timestamp>` (so rollback is a single command), install the snapshot, and restart.
5. Poll `/healthz` until it returns 200, or print logs + rollback instructions on a 60-second timeout.

By default the downloaded snapshot is staged in a `0700` private `mktemp` directory with the file itself at `0600`, and is deleted after a successful restore. Pass `--keep-backup ./pulse-backup.db` to also keep an offline copy.

### 💾 Prefer a one-click manual backup? Use the admin panel

Log in to `/admin` and look at the top-right icon bar — there is a new **Download Backup** button (download icon, emerald hover). Click once and the browser saves `pulse-backup-<UTC-timestamp>.db`. The file is byte-for-byte the **same consistent hot snapshot** `pulse-backup` / `migrate.sh` pull over the CLI (backed by bbolt's `Tx.WriteTo`), so you can feed it straight into `sudo pulse-restore <file>` on any fresh host. Handy when you have no SSH, want an ad-hoc backup before a risky change, or just want an extra safety copy before a migration.

### 🔐 Security notes (30-second read)

- **Use HTTPS or an SSH tunnel.** The snapshot carries the admin password hash and every per-system shared secret — shipping it over plaintext HTTP across the internet is as good as publishing your keys. The script warns on non-localhost `http://`. If you don't have HTTPS on the old host:
  ```bash
  ssh -fN -L 8008:localhost:8008 user@OLD_HOST
  sudo pulse-migrate --from http://localhost:8008
  ```
- **Avoid `--password 'plaintext'`.** Argv is visible to every local user via `ps`. Prefer the interactive prompt (no flag) or the `PASSWORD=...` environment variable.
- **Treat the backup file as the live DB.** Keep it `0600` (the script does), move it over an encrypted channel, and delete it when you're done.
- **The server already does the heavy lifting**: 5 failed logins → IP locked for 15 min, bcrypt password hashing, `/api/admin/backup` accepts **only** `Authorization: Bearer` (no `?token=` query, to keep tokens out of nginx access logs and shell history), and every backup pull writes an audit log line including the caller's IP.

### 🔁 Repoint clients (only if the URL actually changed)

```bash
# Linux (systemd client)
sudo sed -i 's#http://OLD_HOST:8008#http://NEW_HOST:8008#g' \
  /etc/systemd/system/pulse-client.service
sudo systemctl daemon-reload && sudo systemctl restart pulse-client
```

### 🛡️ Rollback

The previous `metrics.db` is preserved as `metrics.db.pre-restore-<timestamp>`, so one command reverts the migration:

```bash
# Standalone binary
sudo systemctl stop pulse-server
sudo cp /opt/pulse/data/metrics.db.pre-restore-* /opt/pulse/data/metrics.db
sudo systemctl start pulse-server

# Docker
docker compose stop
cp datatz/metrics.db.pre-restore-* datatz/metrics.db
docker compose up -d
```

Once you've verified `/admin` login works, the system list is complete, and TCPing charts render, delete the `.pre-restore-*` files.

### 📅 Bonus: periodic backups

The same scripts make good cron fodder for zero-downtime backups (env var keeps the password out of `ps`):

```bash
# Daily at 03:00 UTC
0 3 * * * PASSWORD='YourAdminPW' /opt/pulse/scripts/backup.sh \
  --server http://127.0.0.1:8008 \
  --output /var/backups/pulse/pulse-$(date -u +\%Y\%m\%d).db
```

### ⚠️ Gotchas

- **The backup file is the keys to the kingdom.** It embeds every per-system shared secret and the admin password hash. Treat it with the same care you'd treat the live DB — file permissions, transport encryption.
- **Never run two servers against the same client fleet.** Each client will report to whichever server answers first, so data will split across them. Take the old host offline once the new one is verified.
- **Full flag references**: `pulse-migrate --help`, `pulse-backup --help`, `pulse-restore --help` (or run the underlying `/opt/pulse/scripts/*.sh --help`).

---

## ✨ New Features

- Privacy Mode
- Logo and Name Customization
- CPU Type Detection
- One-Click Client Deployment

---

## 📄 License

[MIT](LICENSE)

