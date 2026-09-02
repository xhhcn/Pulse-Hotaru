# Pulse-Hotaru

Pulse 的 Hotaru 主题拓展发行版。  
保留 Pulse 后端与数据兼容，仅聚焦于 Hotaru 风格前端与发布分离。

## 核心说明

- 独立仓库：`xhhcn/Pulse-Hotaru`
- Docker 镜像：`xhh1128/pulse-hotaru`
- 数据兼容：可直接复用原有 `metrics.db`
- 客户端安装：继续使用 Pulse 官方客户端脚本

## 快速安装（服务端）

### 方式 1：一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/xhhcn/Pulse-Hotaru/main/install-pulse-server.sh | sudo bash
```

安装完成后访问：

```text
http://YOUR_IP:8008
```

### 方式 2：Docker Compose

```bash
mkdir pulse && cd pulse
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse-Hotaru/main/docker-compose.yaml -o docker-compose.yaml
docker compose up -d
```

## 从 Pulse 无损切换到 Pulse-Hotaru

只替换服务端二进制，不删除数据目录：

### amd64

```bash
sudo systemctl stop pulse-server
sudo wget https://github.com/xhhcn/Pulse-Hotaru/releases/latest/download/pulse-server-standalone-linux-amd64 -O /opt/pulse/pulse-server
sudo chmod +x /opt/pulse/pulse-server
sudo systemctl start pulse-server
```

### arm64

```bash
sudo systemctl stop pulse-server
sudo wget https://github.com/xhhcn/Pulse-Hotaru/releases/latest/download/pulse-server-standalone-linux-arm64 -O /opt/pulse/pulse-server
sudo chmod +x /opt/pulse/pulse-server
sudo systemctl start pulse-server
```

> 以上操作不会删除 `/opt/pulse/data/metrics.db`。

## 客户端安装（保持不变）

```bash
curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- \
  --id <ID> --server <SERVER_URL> --secret <SECRET>
```

## 升级

- Docker：拉取新镜像后重建容器
- 二进制：下载最新 `pulse-server-standalone-*` 覆盖 `/opt/pulse/pulse-server`

## 卸载

### 仅卸载程序（保留数据）

```bash
sudo systemctl stop pulse-server && sudo systemctl disable pulse-server && \
sudo rm -f /usr/local/bin/pulse-migrate /usr/local/bin/pulse-backup /usr/local/bin/pulse-restore && \
sudo rm -f /opt/pulse/pulse-server /etc/systemd/system/pulse-server.service && \
sudo rm -rf /opt/pulse/scripts && \
sudo systemctl daemon-reload
```

### 完全卸载（删除全部数据，不可恢复）

```bash
sudo systemctl stop pulse-server && sudo systemctl disable pulse-server && \
sudo rm -f /usr/local/bin/pulse-migrate /usr/local/bin/pulse-backup /usr/local/bin/pulse-restore && \
sudo rm -f /etc/systemd/system/pulse-server.service && \
sudo rm -rf /opt/pulse && \
sudo systemctl daemon-reload
```

## 生产部署建议

- **资源**：服务端为单二进制，1 核 2G 的 VPS 足够。实测 1000 个客户端每 3 秒推送一次并各带 TCPing 结果时，单核 CPU 占用约 25%，常驻内存约 30 MB。
- **TCPing 数据量**：历史保留 24 小时，磁盘占用约为 `客户端数 × 目标数 × (86400 / 间隔秒) × 0.4 KB`。客户端很多时请把间隔保持在 60 秒以上、目标数控制在 3 到 5 个。
- **反向代理 / CDN**：服务端只信任本机回环和 `TRUSTED_PROXIES`（逗号分隔的 IP 或 CIDR）转发的 `X-Forwarded-For`。若前面还有一层反代或 CDN，请设置该变量，否则登录限流与 SSE 连接上限会按代理 IP 计数。
- **SSE 上限**：匿名实时流默认全局 2000 路、单 IP 200 路，可用 `SSE_MAX_STREAMS` 与 `SSE_MAX_STREAMS_PER_IP` 调整；管理员会话不受限制。
- **Docker**：`docker-compose.yaml` 已设置 45 秒优雅停止，请勿缩短，否则强制退出可能损坏数据库。

## 发布页

- Releases: [https://github.com/xhhcn/Pulse-Hotaru/releases](https://github.com/xhhcn/Pulse-Hotaru/releases)
- Docker Hub: [https://hub.docker.com/r/xhh1128/pulse-hotaru](https://hub.docker.com/r/xhh1128/pulse-hotaru)

---

Sponsored by [DokiDoki CDN](https://www.dooki.cloud)
