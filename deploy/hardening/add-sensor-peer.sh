#!/usr/bin/env bash
# Allow a sensor into the WireGuard network (run as root on the nyctala host).
#
#   nyctala-add-sensor-peer <name> <sensor-public-key> <wireguard-ip>
#   nyctala-add-sensor-peer vps-a 'base64key=' 10.66.0.11
#
# Only the sensor's PUBLIC key is stored here: this host holds no secret that
# lets it into a sensor. Each peer may only use its own /32.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $# -eq 3 ]] || { echo "usage: $0 <name> <public-key> <wireguard-ip>" >&2; exit 2; }
name=$1 key=$2 ip=$3

[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "invalid name" >&2; exit 2; }
[[ $key =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$ ]] || { echo "invalid WireGuard public key" >&2; exit 2; }
[[ $ip =~ ^10\.66\.0\.([0-9]{1,3})$ && ${BASH_REMATCH[1]} -ge 2 && ${BASH_REMATCH[1]} -le 254 ]] \
  || { echo "ip must be 10.66.0.2-254" >&2; exit 2; }

conf=/etc/wireguard/wg0.conf
if grep -q -- "$key" "$conf" || grep -q "AllowedIPs = $ip/32" "$conf"; then
  echo "key or address already in use" >&2
  exit 1
fi
printf '\n# sensor %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' "$name" "$key" "$ip" >>"$conf"
wg syncconf wg0 <(wg-quick strip wg0)
echo "added $name ($ip)"
