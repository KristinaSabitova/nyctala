#!/usr/bin/env bash
# One-time (idempotent) hardening of a fresh Debian 13 / Ubuntu 24.04 VPS for nyctala.
#
# Run as root on the new server, from the uploaded deploy/ directory:
#
#   ADMIN_USER=kris ADMIN_PUBKEY=/root/kris_nyctala.pub ADMIN_V4=203.0.113.10/32 \
#   SENSORS_V4=198.51.100.20/32,198.51.100.21/32 ./hardening/bootstrap.sh
#
#   ADMIN_USER    the only account allowed to log in over SSH
#   ADMIN_PUBKEY  file with that account's public key (a key used for this server only)
#   ADMIN_V4      comma-separated IPv4 address(es)/CIDR allowed to reach SSH
#   SENSORS_V4    comma-separated sensor public IPv4s allowed to reach WireGuard
#                 (default 0.0.0.0/0: WireGuard ignores unauthenticated packets)
#   WG_PORT       WireGuard UDP port (default 51820)
#   WG_ADDR       WireGuard address of this host (default 10.66.0.1/24)
#
# Keep your current root session open until you have logged in again as
# ADMIN_USER: this script turns off root and password logins.

set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${ADMIN_USER:?set ADMIN_USER}"
: "${ADMIN_PUBKEY:?set ADMIN_PUBKEY (path to a .pub file)}"
: "${ADMIN_V4:?set ADMIN_V4 (your IP/CIDR for SSH)}"
SENSORS_V4="${SENSORS_V4:-0.0.0.0/0}"
WG_PORT="${WG_PORT:-51820}"
WG_ADDR="${WG_ADDR:-10.66.0.1/24}"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ $ADMIN_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid ADMIN_USER"
[[ $WG_PORT =~ ^[0-9]{1,5}$ ]] || die "invalid WG_PORT"
[[ -s $ADMIN_PUBKEY ]] || die "$ADMIN_PUBKEY is empty or missing"
ssh-keygen -l -f "$ADMIN_PUBKEY" >/dev/null || die "$ADMIN_PUBKEY is not a valid public key"
cidr_list() {
  local item
  IFS=',' read -ra items <<<"$1"
  for item in "${items[@]}"; do
    [[ $item =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || die "not an IPv4 address/CIDR: $item"
  done
  printf '%s' "${1//,/, }"
}
ADMIN_SET="$(cidr_list "$ADMIN_V4")"
SENSORS_SET="$(cidr_list "$SENSORS_V4")"

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q full-upgrade
apt-get -y -q install --no-install-recommends \
  nftables wireguard-tools unattended-upgrades apt-listchanges \
  docker.io rsync rclone restic ca-certificates
# Debian 13 ships the client separately (docker-cli); Ubuntu 24.04 bundles it.
command -v docker >/dev/null || apt-get -y -q install --no-install-recommends docker-cli
apt-get -y -q install --no-install-recommends docker-compose-v2 2>/dev/null \
  || apt-get -y -q install --no-install-recommends docker-compose
docker compose version >/dev/null || die "docker compose plugin missing"

log "admin user $ADMIN_USER"
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$ADMIN_USER"
fi
usermod -aG sudo "$ADMIN_USER"
install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
install -m 600 -o "$ADMIN_USER" -g "$ADMIN_USER" "$ADMIN_PUBKEY" "/home/$ADMIN_USER/.ssh/authorized_keys"
install -d -m 750 -o "$ADMIN_USER" -g "$ADMIN_USER" /opt/nyctala

log "ssh: keys only, no root, only $ADMIN_USER"
[[ -s /home/$ADMIN_USER/.ssh/authorized_keys ]] || die "refusing to lock SSH: no key for $ADMIN_USER"
sed "s/__ADMIN_USER__/$ADMIN_USER/" "$HERE/sshd_nyctala.conf" >/etc/ssh/sshd_config.d/10-nyctala.conf
chmod 644 /etc/ssh/sshd_config.d/10-nyctala.conf
sshd -t || die "sshd configuration invalid; not reloading"
systemctl reload ssh 2>/dev/null || systemctl reload sshd

log "firewall (nftables)"
sed -e "s|__ADMIN_V4__|$ADMIN_SET|" -e "s|__SENSORS_V4__|$SENSORS_SET|" -e "s|__WG_PORT__|$WG_PORT|" \
  "$HERE/nftables.conf" >/etc/nftables.d-nyctala.conf.new
nft -c -f /etc/nftables.d-nyctala.conf.new || die "nftables rules invalid; not applying"
mv /etc/nftables.d-nyctala.conf.new /etc/nftables.d-nyctala.conf
# Replace the distribution file: its `flush ruleset` would wipe Docker's rules
# whenever nftables.service restarts.
printf '#!/usr/sbin/nft -f\ninclude "/etc/nftables.d-nyctala.conf"\n' >/etc/nftables.conf
nft -f /etc/nftables.d-nyctala.conf
systemctl enable --now nftables

log "wireguard ($WG_ADDR, udp/$WG_PORT)"
install -d -m 700 /etc/wireguard
if [[ ! -s /etc/wireguard/server.key ]]; then
  (umask 077 && wg genkey >/etc/wireguard/server.key)
fi
wg pubkey </etc/wireguard/server.key >/etc/wireguard/server.pub
if [[ ! -s /etc/wireguard/wg0.conf ]]; then
  (
    umask 077
    printf '[Interface]\nAddress = %s\nListenPort = %s\nPrivateKey = %s\n' \
      "$WG_ADDR" "$WG_PORT" "$(cat /etc/wireguard/server.key)" >/etc/wireguard/wg0.conf
  )
fi
systemctl enable --now wg-quick@wg0

log "kernel and docker settings"
install -m 644 "$HERE/99-nyctala-sysctl.conf" /etc/sysctl.d/99-nyctala.conf
sysctl --system >/dev/null
install -d /etc/docker
install -m 644 "$HERE/daemon.json" /etc/docker/daemon.json
# ingest is published on the WireGuard address: Docker must start after wg0.
install -d /etc/systemd/system/docker.service.d
printf '[Unit]\nWants=wg-quick@wg0.service\nAfter=wg-quick@wg0.service\n' \
  >/etc/systemd/system/docker.service.d/10-after-wireguard.conf
systemctl daemon-reload
systemctl enable docker
systemctl restart docker

log "automatic security updates"
install -m 644 "$HERE/52-nyctala-unattended-upgrades" /etc/apt/apt.conf.d/52-nyctala-unattended-upgrades
install -m 644 "$HERE/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
systemctl enable --now unattended-upgrades

log "persistent journal"
install -d /var/log/journal /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\nSystemMaxUse=1G\n' >/etc/systemd/journald.conf.d/nyctala.conf
systemctl restart systemd-journald

log "off-site shipping and backups (installed, not enabled until configured)"
install -d -m 700 /etc/nyctala /var/lib/nyctala-offsite /var/lib/nyctala-offsite/outbox
install -d -m 755 /var/lib/nyctala-offsite/anchors
install -m 755 "$HERE/../offsite/nyctala-offsite.sh" /usr/local/sbin/nyctala-offsite
install -m 755 "$HERE/../offsite/nyctala-backup.sh" /usr/local/sbin/nyctala-backup
install -m 755 "$HERE/add-sensor-peer.sh" /usr/local/sbin/nyctala-add-sensor-peer
install -m 644 "$HERE"/../offsite/*.service "$HERE"/../offsite/*.timer /etc/systemd/system/
systemctl daemon-reload

cat <<EOF

Done. Next steps:
  1. From a NEW terminal, check you can log in:  ssh $ADMIN_USER@<this server>
  2. Set a sudo password for $ADMIN_USER:        passwd $ADMIN_USER
  3. WireGuard public key of this server (give it to the sensors):
       $(cat /etc/wireguard/server.pub)
  4. Configure off-site storage, then enable the timers (deploy/README.md).
EOF
