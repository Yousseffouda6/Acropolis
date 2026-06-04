#!/usr/bin/env bash
#
# Acropolis Notes — server-side deploy / redeploy script (Phase 3).
# ----------------------------------------------------------------------------
# Idempotent: safe to run repeatedly. A full (re)deploy is one command:
#
#     ./deploy.sh
#
# It runs on the cloud host as the non-root 'ubuntu' user (which has sudo). It:
#   1. installs docker.io + git (if missing),
#   2. enables + starts the Docker service,
#   3. clones the repo or pulls the latest,
#   4. builds the image, and
#   5. (re)runs the container bound to LOOPBACK ONLY (127.0.0.1:5000).
#
# SECURITY: the container is intentionally published to 127.0.0.1 only — never to
# 0.0.0.0. The app (which has effectively unauthenticated RCE by design) is reached
# solely through an SSH local port-forward. See infra/deploy.md and
# writeups/phase-3-cloud.md. Do not change the bind to a public interface.
# ----------------------------------------------------------------------------
set -euo pipefail

# --- Config (override via environment if you must) --------------------------
REPO_URL="${REPO_URL:-https://github.com/Yousseffouda6/Acropolis.git}"
APP_DIR="${APP_DIR:-$HOME/Acropolis}"
BRANCH="${BRANCH:-main}"
IMAGE="${IMAGE:-acropolis-notes}"
CONTAINER="${CONTAINER:-acropolis-notes}"
BIND="${BIND:-127.0.0.1:5000:5000}"   # loopback only — do NOT use 0.0.0.0

log() { printf '\n\033[1;32m[deploy]\033[0m %s\n' "$*"; }

# --- 1. Base packages: Docker + git -----------------------------------------
if ! command -v docker >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1; then
  log "Installing docker.io and git via apt"
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io git
else
  log "docker and git already present — skipping apt install"
fi

# --- 2. Enable + start the Docker service -----------------------------------
log "Enabling the docker service"
sudo systemctl enable --now docker

# --- 3. Clone or pull the repo (idempotent) ---------------------------------
if [ -d "$APP_DIR/.git" ]; then
  log "Updating existing checkout in $APP_DIR"
  git -C "$APP_DIR" fetch --depth 1 origin "$BRANCH"
  git -C "$APP_DIR" reset --hard "origin/$BRANCH"
else
  log "Cloning $REPO_URL into $APP_DIR"
  git clone "$REPO_URL" "$APP_DIR"
fi

# --- 4. Build the image -----------------------------------------------------
log "Building image '$IMAGE' from $APP_DIR/app"
sudo docker build -t "$IMAGE" "$APP_DIR/app"

# --- 5. (Re)run the container -----------------------------------------------
log "Removing any existing container named '$CONTAINER'"
sudo docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

log "Starting '$CONTAINER' bound to $BIND (loopback only), restart=unless-stopped"
sudo docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p "$BIND" \
  "$IMAGE"

log "Container status:"
sudo docker ps --filter "name=$CONTAINER" \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

cat <<'EOF'

Deployed. The app listens on 127.0.0.1:5000 on the host ONLY.
Reach it from your workstation via an SSH tunnel:

    ssh -i <KEY>.pem -L 5000:localhost:5000 ubuntu@<PUBLIC_IP>

then browse http://localhost:5000 on your workstation.
EOF
