#!/usr/bin/env bash
# Ship what proves the SIEM's history off the SIEM (run by nyctala-offsite.timer).
#
#   anchors    current hash-chain heads (nyctala integrity anchor); also kept
#              locally, read-only for the detect container
#   journal    this host's own journal since the last run (ssh, sudo, docker...)
#   containers nyctala container logs since the last run
#
# Files go to an outbox and are moved to OFFSITE_REMOTE with --immutable, so an
# object that already exists off-site is never replaced. With a WORM bucket and
# a key without delete rights, a compromised SIEM cannot rewrite what it shipped.

set -euo pipefail
umask 077
# shellcheck source=/dev/null
source /etc/nyctala/offsite.env
: "${OFFSITE_REMOTE:?}" "${COMPOSE_DIR:?}"
export RCLONE_CONFIG=/etc/nyctala/rclone.conf

state=/var/lib/nyctala-offsite
outbox=$state/outbox
mkdir -p "$outbox"  # rclone move removes it once emptied
now=$(date -u +%s)
stamp=$(date -u -d "@$now" +%Y%m%dT%H%M%SZ)
since=$(cat "$state/last-run" 2>/dev/null || echo $((now - 3600)))
compose=(docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_DIR/docker-compose.yml")

anchors=$("${compose[@]}" exec -T detect nyctala integrity anchor)
if [[ -n $anchors ]]; then
  printf '%s\n' "$anchors" >"$outbox/anchors-$stamp.ndjson"
  (umask 022 && printf '%s\n' "$anchors" >>"$state/anchors/anchors.ndjson")
fi

journalctl --since "@$since" --until "@$now" -o json --no-pager | gzip -9 >"$outbox/journal-$stamp.json.gz"
"${compose[@]}" logs --no-color --timestamps --since "$since" --until "$now" 2>&1 \
  | gzip -9 >"$outbox/containers-$stamp.log.gz"

sha256sum "$outbox"/*-"$stamp".* >"$outbox/SHA256SUMS-$stamp"
rclone move --immutable --no-traverse "$outbox" "$OFFSITE_REMOTE/$(date -u +%Y/%m/%d)"
echo "$now" >"$state/last-run"
