#!/usr/bin/env bash
# Prepare a sensor host (run as root): WireGuard to nyctala, no way back in, Vector config.
#
#   SENSOR_WG_IP=10.66.0.11 NYCTALA_ENDPOINT=<siem-public-ip>:51820 \
#   NYCTALA_SERVER_PUBKEY='<key printed by bootstrap.sh>' ./sensor/install-sensor.sh
#
# Vector itself must already be installed from its official packages
# (https://vector.dev/docs/setup/installation/). The ingest token is not taken
# here: put it in /etc/default/vector yourself (see the end of this script).
#
# The sensor keeps its own WireGuard private key. The SIEM only learns the public
# key, and the firewall below drops any connection the SIEM side tries to open:
# a compromised SIEM cannot use the tunnel to reach the sensor.

set -euo pipefail
umask 022
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${SENSOR_WG_IP:?}" "${NYCTALA_ENDPOINT:?}" "${NYCTALA_SERVER_PUBKEY:?}"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $SENSOR_WG_IP =~ ^10\.66\.0\.[0-9]{1,3}$ ]] || { echo "SENSOR_WG_IP must be in 10.66.0.0/24" >&2; exit 2; }
[[ $NYCTALA_SERVER_PUBKEY =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$ ]] || { echo "invalid server key" >&2; exit 2; }
command -v vector >/dev/null || { echo "install Vector first (official packages)" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get -y -q install --no-install-recommends wireguard-tools nftables

install -d -m 700 /etc/wireguard
if [[ ! -s /etc/wireguard/nyctala.key ]]; then
  (umask 077 && wg genkey >/etc/wireguard/nyctala.key)
fi
(
  umask 077
  cat >/etc/wireguard/nyctala.conf <<CONF
[Interface]
Address = $SENSOR_WG_IP/32
PrivateKey = $(cat /etc/wireguard/nyctala.key)

[Peer]
PublicKey = $NYCTALA_SERVER_PUBKEY
Endpoint = $NYCTALA_ENDPOINT
# Only the SIEM's address goes through the tunnel.
AllowedIPs = 10.66.0.1/32
PersistentKeepalive = 25
CONF
)

# Nothing may come in through the tunnel except replies to what we send.
cat >/etc/nftables-nyctala-sensor.conf <<'NFT'
table inet nyctala_sensor
delete table inet nyctala_sensor
table inet nyctala_sensor {
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "nyctala" ct state established,related accept
        iifname "nyctala" drop
    }
}
NFT
nft -c -f /etc/nftables-nyctala-sensor.conf
nft -f /etc/nftables-nyctala-sensor.conf
grep -q nftables-nyctala-sensor /etc/nftables.conf 2>/dev/null \
  || printf '\ninclude "/etc/nftables-nyctala-sensor.conf"\n' >>/etc/nftables.conf
systemctl enable nftables

install -m 644 "$HERE/vector.yaml" /etc/vector/nyctala.yaml
systemctl enable --now wg-quick@nyctala

cat <<MSG

Sensor public key (on the SIEM: nyctala-add-sensor-peer <name> <key> $SENSOR_WG_IP):
  $(wg pubkey </etc/wireguard/nyctala.key)

Then put the ingest token in /etc/default/vector (root, 0600):
  NYCTALA_TOKEN=nyc_...
  VECTOR_CONFIG=/etc/vector/nyctala.yaml
and restart Vector:  systemctl restart vector
MSG
