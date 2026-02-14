#!/bin/bash
#
# Pulse Client Installation Script for Linux
# Usage: curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | bash -s -- --id YOUR_ID --server http://YOUR_SERVER:8080
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/pulse"
SERVICE_NAME="pulse-client"
UPDATE_SERVICE_NAME="pulse-client-update"
GITHUB_REPO="https://raw.githubusercontent.com/xhhcn/Pulse/main/client"
CLIENT_PORT="9090"
AGENT_NAME=""
SECRET=""
AUTO_UPDATE=true
UPDATE_INTERVAL="daily"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                  Pulse Client Installer                   ║"
    echo "║           Lightweight Server Monitoring Agent             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print message functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (use sudo)"
    fi
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --id)
                AGENT_ID="$2"
                shift 2
                ;;
            --name|--agent-name)
                AGENT_NAME="$2"
                shift 2
                ;;
            --server)
                SERVER_BASE="$2"
                shift 2
                ;;
            --port)
                CLIENT_PORT="$2"
                shift 2
                ;;
            --secret)
                SECRET="$2"
                shift 2
                ;;
            --auto-update)
                AUTO_UPDATE=true
                shift
                ;;
            --no-auto-update)
                AUTO_UPDATE=false
                shift
                ;;
            --update-interval)
                UPDATE_INTERVAL="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
}

# Show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --id ID              Agent ID (required, must match server config)"
    echo "  --name NAME          Agent display name (optional, defaults to ID)"
    echo "  --server URL         Server base URL (required, e.g., http://your-server:8080)"
    echo "  --port PORT          Client port (optional, default: 9090)"
    echo "  --secret SECRET      Secret for authentication (optional, if server requires it)"
    echo "  --auto-update        Enable auto-update (default: enabled)"
    echo "  --no-auto-update     Disable auto-update"
    echo "  --update-interval T  Update check interval (default: daily, e.g., hourly, weekly, *-*-* 03:00:00)"
    echo "  --help, -h           Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --id my-server-1 --server http://monitor.example.com:8080 --secret my-secret"
    echo "  $0 --id my-server-1 --server http://monitor.example.com:8080 --no-auto-update"
    echo "  $0 --id my-server-1 --server http://monitor.example.com:8080 --update-interval 'weekly'"
    echo ""
    echo "Or using curl:"
    echo "  curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- --id my-server-1 --server http://monitor.example.com:8080 --secret my-secret"
}

# Prompt for required values if not provided
prompt_values() {
    if [ -z "$AGENT_ID" ]; then
        read -p "Enter Agent ID (must match server config): " AGENT_ID
        [ -z "$AGENT_ID" ] && error "Agent ID is required"
    fi
    
    if [ -z "$SERVER_BASE" ]; then
        read -p "Enter Server URL (e.g., http://your-server:8080): " SERVER_BASE
        [ -z "$SERVER_BASE" ] && error "Server URL is required"
    fi
    
    if [ -z "$AGENT_NAME" ]; then
        AGENT_NAME="$AGENT_ID"
    fi
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            BINARY_NAME="probe-client"
            ;;
        aarch64|arm64)
            BINARY_NAME="probe-client-arm64"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac
    info "Detected architecture: $ARCH"
}

# Download binary
download_binary() {
    info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    
    info "Downloading Pulse client..."
    DOWNLOAD_URL="${GITHUB_REPO}/${BINARY_NAME}"
    
    if command -v curl &> /dev/null; then
        curl -sSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/probe-client" || error "Failed to download binary"
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/probe-client" || error "Failed to download binary"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
    
    chmod +x "$INSTALL_DIR/probe-client"
    success "Downloaded and installed probe-client"
}

# Create systemd service
create_service() {
    info "Creating systemd service..."
    
    # Build environment variables for systemd service
    ENV_LINES="Environment=\"AGENT_ID=${AGENT_ID}\"\n"
    if [ -n "$AGENT_NAME" ]; then
        ENV_LINES="${ENV_LINES}Environment=\"AGENT_NAME=${AGENT_NAME}\"\n"
    fi
    ENV_LINES="${ENV_LINES}Environment=\"SERVER_BASE=${SERVER_BASE}\"\n"
    ENV_LINES="${ENV_LINES}Environment=\"CLIENT_PORT=${CLIENT_PORT}\"\n"
    if [ -n "$SECRET" ]; then
        ENV_LINES="${ENV_LINES}Environment=\"SECRET=${SECRET}\"\n"
    fi
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Pulse Monitoring Client
After=network.target

[Service]
Type=simple
$(echo -e "$ENV_LINES")
ExecStart=${INSTALL_DIR}/probe-client
Restart=always
RestartSec=10
# Log to systemd journal with size limits
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pulse-client
# Limit journal storage: max 50MB for this service, drop oldest when full
LogRateLimitIntervalSec=30
LogRateLimitBurst=50

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    success "Service created and started"
}

# Create auto-update script
create_update_script() {
    info "Creating auto-update script..."
    
    cat > "${INSTALL_DIR}/update.sh" << 'UPDATEEOF'
#!/bin/bash
#
# Pulse Client Auto-Update Script
# Checks for new version and updates if available
#

INSTALL_DIR="/opt/pulse"
SERVICE_NAME="pulse-client"
GITHUB_REPO="https://raw.githubusercontent.com/xhhcn/Pulse/main/client"
CURRENT_BINARY="${INSTALL_DIR}/probe-client"
TEMP_BINARY="${INSTALL_DIR}/probe-client.tmp"

# Log to stdout (captured by systemd journal)
log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1"
}

# Detect architecture
detect_arch() {
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64|amd64)  echo "probe-client" ;;
        aarch64|arm64)  echo "probe-client-arm64" ;;
        *)
            log_msg "[ERROR] Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Cleanup temp file on exit
cleanup() {
    rm -f "$TEMP_BINARY"
}
trap cleanup EXIT

main() {
    local binary_name
    binary_name=$(detect_arch)
    local download_url="${GITHUB_REPO}/${binary_name}"
    
    log_msg "[INFO] Checking for updates..."
    
    # Download to temp file
    if command -v curl &> /dev/null; then
        if ! curl -sSL --connect-timeout 15 --max-time 120 "$download_url" -o "$TEMP_BINARY" 2>/dev/null; then
            log_msg "[WARN] Download failed, will retry next cycle"
            exit 0
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q --timeout=120 "$download_url" -O "$TEMP_BINARY" 2>/dev/null; then
            log_msg "[WARN] Download failed, will retry next cycle"
            exit 0
        fi
    else
        log_msg "[ERROR] Neither curl nor wget found"
        exit 1
    fi
    
    # Validate downloaded file (must be non-empty and executable ELF)
    if [ ! -s "$TEMP_BINARY" ]; then
        log_msg "[WARN] Downloaded file is empty, skipping update"
        exit 0
    fi
    
    # Check if it's a valid ELF binary
    if ! head -c 4 "$TEMP_BINARY" | grep -q "ELF" 2>/dev/null; then
        log_msg "[WARN] Downloaded file is not a valid binary, skipping update"
        exit 0
    fi
    
    # Compare checksums
    if [ -f "$CURRENT_BINARY" ]; then
        local current_hash new_hash
        current_hash=$(sha256sum "$CURRENT_BINARY" 2>/dev/null | awk '{print $1}')
        new_hash=$(sha256sum "$TEMP_BINARY" 2>/dev/null | awk '{print $1}')
        
        if [ "$current_hash" = "$new_hash" ]; then
            log_msg "[INFO] Already up to date (hash: ${current_hash:0:12}...)"
            exit 0
        fi
        
        log_msg "[INFO] New version detected (${current_hash:0:12}... -> ${new_hash:0:12}...)"
    else
        log_msg "[INFO] No existing binary found, installing..."
    fi
    
    # Replace binary and restart
    chmod +x "$TEMP_BINARY"
    mv -f "$TEMP_BINARY" "$CURRENT_BINARY"
    
    # Restart service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"
        log_msg "[INFO] Updated and restarted ${SERVICE_NAME}"
    else
        log_msg "[INFO] Updated binary, service is not running"
    fi
}

main "$@"
UPDATEEOF
    
    chmod +x "${INSTALL_DIR}/update.sh"
    success "Auto-update script created: ${INSTALL_DIR}/update.sh"
}

# Create auto-update systemd timer
create_update_timer() {
    info "Setting up auto-update timer (interval: ${UPDATE_INTERVAL})..."
    
    # Create the oneshot service for update
    cat > /etc/systemd/system/${UPDATE_SERVICE_NAME}.service << EOF
[Unit]
Description=Pulse Client Auto-Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/update.sh
# Limit resources for the update check
Nice=19
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pulse-update
# Prevent excessive logging from update script
LogRateLimitIntervalSec=60
LogRateLimitBurst=20
EOF

    # Create the timer
    cat > /etc/systemd/system/${UPDATE_SERVICE_NAME}.timer << EOF
[Unit]
Description=Pulse Client Auto-Update Timer

[Timer]
OnCalendar=${UPDATE_INTERVAL}
# Random delay up to 1 hour to avoid all clients updating simultaneously
RandomizedDelaySec=3600
# Run missed checks after boot
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable ${UPDATE_SERVICE_NAME}.timer
    systemctl start ${UPDATE_SERVICE_NAME}.timer
    
    success "Auto-update timer enabled (interval: ${UPDATE_INTERVAL})"
}

# Show status
show_status() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Pulse Client Installed Successfully!           ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Configuration:"
    echo "  Agent ID:      $AGENT_ID"
    echo "  Server:        $SERVER_BASE"
    echo "  Client Port:   $CLIENT_PORT"
    if [ -n "$SECRET" ]; then
        echo "  Secret:        ${SECRET:0:4}**** (hidden)"
    fi
    echo "  Install Dir:   $INSTALL_DIR"
    echo "  Auto-Update:   $([ "$AUTO_UPDATE" = true ] && echo "Enabled (${UPDATE_INTERVAL})" || echo "Disabled")"
    echo ""
    echo "Service Commands:"
    echo "  Check status:   systemctl status ${SERVICE_NAME}"
    echo "  View logs:      journalctl -u ${SERVICE_NAME} -f"
    echo "  View all logs:  journalctl -u ${SERVICE_NAME} --no-pager -n 100"
    echo "  Restart:        systemctl restart ${SERVICE_NAME}"
    echo "  Stop:           systemctl stop ${SERVICE_NAME}"
    if [ "$AUTO_UPDATE" = true ]; then
        echo ""
        echo "Auto-Update Commands:"
        echo "  Check timer:    systemctl list-timers ${UPDATE_SERVICE_NAME}.timer"
        echo "  Update now:     systemctl start ${UPDATE_SERVICE_NAME}.service"
        echo "  Update logs:    journalctl -u ${UPDATE_SERVICE_NAME} --no-pager -n 50"
        echo "  Disable:        systemctl stop ${UPDATE_SERVICE_NAME}.timer && systemctl disable ${UPDATE_SERVICE_NAME}.timer"
    fi
    echo ""
    echo "Uninstall:"
    if [ "$AUTO_UPDATE" = true ]; then
        echo "  systemctl stop ${SERVICE_NAME} ${UPDATE_SERVICE_NAME}.timer && \\"
        echo "  systemctl disable ${SERVICE_NAME} ${UPDATE_SERVICE_NAME}.timer && \\"
        echo "  rm -rf ${INSTALL_DIR} /etc/systemd/system/${SERVICE_NAME}.service \\"
        echo "  /etc/systemd/system/${UPDATE_SERVICE_NAME}.service \\"
        echo "  /etc/systemd/system/${UPDATE_SERVICE_NAME}.timer && \\"
        echo "  systemctl daemon-reload"
    else
        echo "  systemctl stop ${SERVICE_NAME} && systemctl disable ${SERVICE_NAME} && \\"
        echo "  rm -rf ${INSTALL_DIR} /etc/systemd/system/${SERVICE_NAME}.service && \\"
        echo "  systemctl daemon-reload"
    fi
    echo ""
}

# Main
main() {
    print_banner
    parse_args "$@"
    check_root
    prompt_values
    detect_arch
    download_binary
    create_service
    
    # Setup auto-update if enabled
    if [ "$AUTO_UPDATE" = true ]; then
        create_update_script
        create_update_timer
    fi
    
    show_status
}

main "$@"

