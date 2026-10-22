#!/usr/bin/env bash
# Deploy the current checkout to the nyctala VPS (run from your machine).
#
#   deploy/deploy.sh <ssh-host>
#
# <ssh-host> is an alias in ~/.ssh/config with the server's address, the admin
# user and a key used for this server only, e.g.:
#
#   Host nyctala
#     HostName <server-ip>
#     User kris
#     IdentityFile ~/.ssh/nyctala_ed25519
#     IdentitiesOnly yes
#
# Only the code is copied (rsync); data stays in the server's Docker volume.
# The build and restart run with sudo, so you will be asked for the sudo password.

set -euo pipefail
host=${1:?usage: deploy/deploy.sh <ssh-host>}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n $(git -C "$root" status --porcelain) ]]; then
  echo "refusing to deploy uncommitted changes" >&2
  exit 1
fi
version=$(git -C "$root" rev-parse --short HEAD)

rsync -az --delete \
  --exclude '.git/' --exclude '.venv/' --exclude 'data/' --exclude 'dist/' \
  --exclude '__pycache__/' --exclude '.*_cache/' --exclude 'deploy/.env' --exclude 'deploy/anchors/' \
  "$root/" "$host:/opt/nyctala/"

ssh -t "$host" "cd /opt/nyctala/deploy && test -f .env || { echo 'missing /opt/nyctala/deploy/.env (see .env.example)'; exit 1; } \
  && sudo NYCTALA_VERSION=$version docker compose up -d --build --remove-orphans \
  && sudo docker compose ps"
