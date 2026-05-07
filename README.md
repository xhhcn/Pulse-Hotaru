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

## 发布页

- Releases: [https://github.com/xhhcn/Pulse-Hotaru/releases](https://github.com/xhhcn/Pulse-Hotaru/releases)
- Docker Hub: [https://hub.docker.com/r/xhh1128/pulse-hotaru](https://hub.docker.com/r/xhh1128/pulse-hotaru)

---

Sponsored by [DokiDoki CDN](https://www.dooki.cloud)
