#!/usr/bin/env bash
# pulse-restore -- swap a Pulse bbolt snapshot into the live install.
#
# Works against BOTH deployment styles — same bbolt file, different
# host path and process manager. Auto-detected, can be forced:
#
#   docker   : docker compose (data at ./datatz/metrics.db or whatever
#              the compose volume mount resolves to; default port 8008)
#   systemd  : standalone binary installed by install-pulse-server.sh
#              (data at /opt/pulse/data/metrics.db, service
#              pulse-server, default port 8008)
#
# Usage:
#   ./scripts/restore.sh <backup.db>                     # auto-detect mode
#   ./scripts/restore.sh --mode systemd <backup.db>      # force binary/systemd
#   ./scripts/restore.sh --mode docker  <backup.db>      # force docker compose
#   ./scripts/restore.sh --data-dir /custom <backup.db>  # override data dir
#   ./scripts/restore.sh -y <backup.db>                  # non-interactive
#
# What it does, in order:
#   1. Sanity-check the incoming file exists, is non-empty, and carries
#      the bbolt magic number in its meta page. Catches truncated SCP
#      transfers, wrong file pasted, or a still-gzipped archive before
#      anything destructive runs.
#   2. Stop the service (docker compose stop / systemctl stop). Both
#      give the backend a graceful SIGTERM so bbolt flushes cleanly.
#   3. Rename the current metrics.db to metrics.db.pre-restore-<utc>
#      so rollback is one command.
#   4. cp (not mv) the incoming file into place. The source snapshot
#      is left intact — useful when restoring from an archived backup.
#   5. Start the service and poll /healthz until it returns 200 or a
#      60-second timeout expires.

set -euo pipefail

COMPOSE_DIR="."
DATA_DIR=""
MODE="auto"
PORT=""
SERVICE_NAME="pulse-server"
INSTALL_DIR="/opt/pulse"
YES="false"
BACKUP=""

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)         MODE="$2"; shift 2 ;;
    --compose-dir)  COMPOSE_DIR="$2"; shift 2 ;;
    --data-dir)     DATA_DIR="$2"; shift 2 ;;
    --port)         PORT="$2"; shift 2 ;;
    --service)      SERVICE_NAME="$2"; shift 2 ;;
    --install-dir)  INSTALL_DIR="$2"; shift 2 ;;
    -y|--yes)       YES="true"; shift ;;
    -h|--help)      usage ;;
    -*)             echo "Unknown flag: $1"; usage ;;
    *)              BACKUP="$1"; shift ;;
  esac
done

if [[ -z "$BACKUP" ]]; then
  echo "error: missing backup file argument" >&2
  usage
fi
if [[ ! -f "$BACKUP" ]]; then
  echo "error: $BACKUP does not exist" >&2
  exit 2
fi

size="$(wc -c <"$BACKUP" | tr -d ' ')"
if [[ "$size" -lt 4096 ]]; then
  echo "error: $BACKUP is suspiciously small (${size} bytes); aborting" >&2
  exit 3
fi
magic_hex="$(dd if="$BACKUP" bs=1 skip=16 count=4 status=none | od -An -tx1 | tr -d ' \n')"
if [[ "$magic_hex" != "edda0ced" ]]; then
  echo "error: $BACKUP does not look like a bbolt file (magic=$magic_hex)" >&2
  echo "       did you forget to gunzip / untar it first?" >&2
  exit 4
fi

# ---- auto-detect deployment mode ----------------------------------------
detect_mode() {
  # Prefer docker if a compose file is present in the given dir and
  # docker is usable. Fall back to systemd if the standalone service
  # unit is present. If neither is obvious, bail out with a helpful
  # message; the operator can force it with --mode.
  if [[ -f "$COMPOSE_DIR/docker-compose.yaml" || -f "$COMPOSE_DIR/docker-compose.yml" ]] \
     && command -v docker >/dev/null 2>&1; then
    echo "docker"; return
  fi
  if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] \
     && command -v systemctl >/dev/null 2>&1; then
    echo "systemd"; return
  fi
  echo ""
}

if [[ "$MODE" == "auto" ]]; then
  MODE="$(detect_mode)"
  if [[ -z "$MODE" ]]; then
    echo "error: could not auto-detect deployment mode." >&2
    echo "       Pass --mode docker or --mode systemd explicitly," >&2
    echo "       or run this script from the directory that contains" >&2
    echo "       your docker-compose.yaml." >&2
    exit 5
  fi
fi

# ---- resolve data dir and port per mode ---------------------------------
case "$MODE" in
  docker)
    cd "$COMPOSE_DIR"
    compose_file="docker-compose.yaml"
    [[ -f docker-compose.yml && ! -f docker-compose.yaml ]] && compose_file="docker-compose.yml"
    if [[ ! -f "$compose_file" ]]; then
      echo "error: no docker-compose.y(a)ml in $(pwd); use --compose-dir" >&2
      exit 5
    fi
    if [[ -z "$DATA_DIR" ]]; then
      # Resolve the host-side data dir from the first bind mount that
      # targets /app/data. Supports both standard docker-compose forms:
      #   volumes:                        (block form)
      #     - ./datatz:/app/data
      #   volumes: ["./datatz:/app/data"] (flow form)
      #   volumes: [./datatz:/app/data]   (unquoted flow form)
      # As well as absolute host paths.
      DATA_DIR="$(awk '
        function extract(line,    h) {
          if (match(line, /[^[:space:]"'"'"',[]+:\/app\/data([:"'"'"',\]]|$)/)) {
            h=substr(line, RSTART, RLENGTH)
            sub(/:\/app\/data.*$/, "", h)
            print h; return 1
          }
          return 0
        }
        /volumes:/ {
          rest=$0
          sub(/^.*volumes:/, "", rest)
          if (rest ~ /\[/) {
            if (extract(rest)) exit
            next
          }
          in_v=1; next
        }
        in_v && /^[[:space:]]*-[[:space:]]/ {
          if (extract($0)) exit
        }
        in_v && /^[^[:space:]]/ {in_v=0}
      ' "$compose_file")"
      if [[ -z "$DATA_DIR" ]]; then
        echo "error: could not auto-detect host data directory; pass --data-dir" >&2
        exit 5
      fi
    fi
    if [[ -z "$PORT" ]]; then
      PORT="$(awk '
        /ports:/ {in_p=1; next}
        in_p && /^[[:space:]]*-[[:space:]]/ {
          line=$0
          sub(/^[[:space:]]*-[[:space:]]+/, "", line)
          gsub(/"/, "", line)
          split(line, a, ":")
          print a[1]; exit
        }
        in_p && /^[^[:space:]]/ {in_p=0}
      ' "$compose_file")"
      [[ -z "$PORT" ]] && PORT=8008
    fi
    ;;
  systemd)
    [[ -z "$DATA_DIR" ]] && DATA_DIR="$INSTALL_DIR/data"
    [[ -z "$PORT" ]] && PORT=8008
    if ! command -v systemctl >/dev/null 2>&1; then
      echo "error: systemctl not found" >&2
      exit 6
    fi
    if [[ ! -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
      echo "error: /etc/systemd/system/${SERVICE_NAME}.service missing" >&2
      echo "       install it first with install-pulse-server.sh, or pass --service" >&2
      exit 7
    fi
    # Root is required to touch /opt/pulse and control the unit.
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "error: systemd mode needs root (re-run with sudo)" >&2
      exit 8
    fi
    ;;
  *)
    echo "error: unknown mode '$MODE' (expected docker|systemd|auto)" >&2
    exit 9
    ;;
esac

mkdir -p "$DATA_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SAVED="$DATA_DIR/metrics.db.pre-restore-${TS}"

echo "About to restore:"
echo "  mode     : $MODE"
echo "  source   : $BACKUP  (${size} bytes)"
echo "  target   : $DATA_DIR/metrics.db"
echo "  old DB   : $SAVED  (kept for rollback)"
if [[ "$YES" != "true" ]]; then
  read -r -p "Proceed? [y/N] " ans
  case "$ans" in
    y|Y|yes|YES) ;;
    *) echo "aborted."; exit 0 ;;
  esac
fi

# ---- stop service -------------------------------------------------------
case "$MODE" in
  docker)
    echo "→ docker compose stop"
    docker compose stop
    ;;
  systemd)
    echo "→ systemctl stop $SERVICE_NAME"
    systemctl stop "$SERVICE_NAME"
    ;;
esac

# ---- swap file ----------------------------------------------------------
if [[ -f "$DATA_DIR/metrics.db" ]]; then
  mv "$DATA_DIR/metrics.db" "$SAVED"
  echo "  preserved old DB as $SAVED"
fi
cp "$BACKUP" "$DATA_DIR/metrics.db"
# bbolt lock sidecar from a different host must not carry over.
rm -f "$DATA_DIR/metrics.db.lock"
# Pin the installed file to 0600. bbolt only enforces the mode when it
# creates a new file, and plain cp honours the caller's umask (usually
# 0022 → 0644), so without this line the restored DB could spend its
# entire life world-readable. The file contains the admin password
# bcrypt hash and every per-system shared secret, so 0600 is the
# correct default regardless of umask.
chmod 600 "$DATA_DIR/metrics.db"
echo "  installed $BACKUP → $DATA_DIR/metrics.db (mode 0600)"

# ---- start service ------------------------------------------------------
case "$MODE" in
  docker)
    echo "→ docker compose up -d"
    docker compose up -d
    ;;
  systemd)
    echo "→ systemctl start $SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    ;;
esac

# ---- wait for health ----------------------------------------------------
echo "→ waiting for /healthz on port ${PORT}"
deadline=$(( $(date +%s) + 60 ))
while (( $(date +%s) < deadline )); do
  code="$(curl -4 -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/healthz" || true)"
  if [[ "$code" == "200" ]]; then
    echo "✓ Service is healthy on port ${PORT}. Restore complete."
    echo "  If everything looks good, you can delete: $SAVED"
    exit 0
  fi
  sleep 2
done

echo "error: /healthz did not reach 200 within 60s" >&2
case "$MODE" in
  docker)
    echo "       recent container logs (via docker compose):" >&2
    # Ask compose itself for the logs — it knows the actual container
    # name it created, which is not necessarily "pulse-monitor". The
    # `>&2 2>&1` dance sends both streams to our stderr without
    # swallowing compose's "no container" warning.
    docker compose logs --tail=60 --no-log-prefix >&2 2>&1 || true
    ;;
  systemd)
    echo "       service logs:" >&2
    journalctl -u "$SERVICE_NAME" -n 60 --no-pager >&2 2>&1 || true
    ;;
esac
echo >&2
echo "To roll back:" >&2
case "$MODE" in
  docker)
    echo "  docker compose stop && cp '$SAVED' '$DATA_DIR/metrics.db' && docker compose up -d" >&2
    ;;
  systemd)
    echo "  systemctl stop $SERVICE_NAME && cp '$SAVED' '$DATA_DIR/metrics.db' && systemctl start $SERVICE_NAME" >&2
    ;;
esac
exit 10
