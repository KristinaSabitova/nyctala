#!/usr/bin/env bash
# Encrypted backup of the nyctala data volume (run by nyctala-backup.timer).
#
# restic encrypts client-side; the password is generated on first run in
# /etc/nyctala/restic.pass. KEEP A COPY OF IT OFF THE SERVER: without it the
# backups cannot be restored. Old snapshots are not pruned from here (the key
# should have no delete rights); expire them with the bucket's lifecycle rules.

set -euo pipefail
umask 077
# shellcheck source=/dev/null
source /etc/nyctala/offsite.env
: "${RESTIC_REPOSITORY:?}" "${COMPOSE_DIR:?}"
export RESTIC_REPOSITORY RCLONE_CONFIG=/etc/nyctala/rclone.conf
export RESTIC_PASSWORD_FILE=/etc/nyctala/restic.pass

if [[ ! -s $RESTIC_PASSWORD_FILE ]]; then
  head -c 48 /dev/urandom | base64 >"$RESTIC_PASSWORD_FILE"
  echo "generated $RESTIC_PASSWORD_FILE - copy it somewhere safe off this server" >&2
fi
restic cat config >/dev/null 2>&1 || restic init

volume=$(docker volume inspect nyctala_nyctala-data --format '{{.Mountpoint}}')
# Parquet files are written aside and renamed, so a live snapshot is consistent.
restic backup --tag nyctala --host "$(hostname)" "$volume" /var/lib/nyctala-offsite/anchors
restic check --read-data-subset=1%
