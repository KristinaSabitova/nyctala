# Deploying nyctala

nyctala runs alone on a dedicated VPS. Sensors push their logs to it through
WireGuard; it never holds credentials for any sensor.

```
[sensor A] --\                                   +-------------- nyctala VPS --------------+
[sensor B] ---+-- WireGuard (udp/51820) --------> | wg0 10.66.0.1                           |
[lab]      --/   Vector -> HTTP NDJSON + token    |   ingest  :8514 (bound to wg0 only)     |
                                                  |   detect  (no network)                  |
                                                  |   /data   Parquet, hash-chained events  |
                                                  +---- anchors, own logs, backups ---------+
                                                                   | rclone --immutable
                                                                   v
                                                       off-site WORM bucket(s)
```

## What protects what

| SPEC rule | Where |
|---|---|
| Push model, no sensor credentials on the SIEM | sensors dial in; the SIEM stores only WireGuard *public* keys |
| No pivot from a compromised SIEM | `sensor/install-sensor.sh`: the sensor drops anything the tunnel tries to open |
| Own keys/users for this VPS | `hardening/bootstrap.sh`: one admin user, a key used only here |
| Default-deny firewall | `hardening/nftables.conf`: SSH from your IP, WireGuard from sensors, ingest only on `wg0` |
| SSH by key only, no root, automatic updates | `hardening/sshd_nyctala.conf`, unattended-upgrades with reboot at 04:30 |
| SIEM's own logs off-site | `offsite/nyctala-offsite.sh` every 5 min: anchors, journal, container logs |
| Encrypted off-site backups | `offsite/nyctala-backup.sh` daily, restic |
| Unprivileged containers, limits, read-only FS | `docker-compose.yml`: uid 10001, `cap_drop: ALL`, `no-new-privileges`, read-only, memory/CPU/PID limits; `detect` has no network |

## 1. Create the server (you)

1. A new Hetzner project for nyctala only (keeps API tokens and access separate).
2. A small VPS, Debian 13 or Ubuntu 24.04. 2 vCPU / 4 GB is plenty for the MVP.
3. A new SSH key used only for this server:
   `ssh-keygen -t ed25519 -f ~/.ssh/nyctala_ed25519 -C nyctala-admin`
4. In `~/.ssh/config`:

   ```
   Host nyctala
     HostName <server-ip>
     User <admin-user>
     IdentityFile ~/.ssh/nyctala_ed25519
     IdentitiesOnly yes
   ```

## 2. Harden it

Copy the deploy directory and your public key, then run the bootstrap as root
(the only time root logs in):

```bash
scp -i ~/.ssh/nyctala_ed25519 -r deploy ~/.ssh/nyctala_ed25519.pub root@<server-ip>:/root/
ssh -i ~/.ssh/nyctala_ed25519 root@<server-ip>
ADMIN_USER=<admin-user> ADMIN_PUBKEY=/root/nyctala_ed25519.pub \
ADMIN_V4=<your-ip>/32 SENSORS_V4=<sensor-a-ip>/32,<sensor-b-ip>/32 \
  /root/deploy/hardening/bootstrap.sh
```

Keep that root session open, check `ssh nyctala` works from a new terminal, then
set the sudo password (`sudo passwd <admin-user>` as root) and close the root
session. Note the WireGuard public key the script prints.

The script is idempotent: run it again to change the allowed IPs.

## 3. Deploy the application

From your machine, on a clean checkout:

```bash
ssh nyctala 'cp /opt/nyctala/deploy/.env.example /opt/nyctala/deploy/.env'   # first time only
deploy/deploy.sh nyctala
```

`deploy.sh` rsyncs the code to `/opt/nyctala` and runs `docker compose up -d --build`.
Data lives in the `nyctala_nyctala-data` volume and survives redeploys.

## 4. Add a sensor

On the sensor (Vector installed from its official packages first):

```bash
SENSOR_WG_IP=10.66.0.11 NYCTALA_ENDPOINT=<server-ip>:51820 \
NYCTALA_SERVER_PUBKEY='<key from step 2>' ./deploy/sensor/install-sensor.sh
```

On nyctala:

```bash
sudo nyctala-add-sensor-peer sensor-a '<sensor public key>' 10.66.0.11
cd /opt/nyctala/deploy && sudo docker compose run --rm ingest sensor add sensor-a
```

The last command prints the ingest token **once**. Put it on the sensor in
`/etc/default/vector` (root, 0600) together with `VECTOR_CONFIG=/etc/vector/nyctala.yaml`,
then `systemctl restart vector`. Revoke with `docker compose run --rm ingest sensor revoke sensor-a`.

## 5. Off-site storage

Create two buckets with **Object Lock / WORM** (any S3-compatible provider that
supports it) and access keys that can write but **not delete or overwrite**.
On nyctala, as root:

```bash
rclone config --config /etc/nyctala/rclone.conf     # remotes nyctala-audit and nyctala-backup
cp /opt/nyctala/deploy/offsite/offsite.env.example /etc/nyctala/offsite.env   # edit it
chmod 600 /etc/nyctala/*
systemctl start nyctala-offsite.service nyctala-backup.service    # first run by hand
systemctl enable --now nyctala-offsite.timer nyctala-backup.timer
```

The first backup generates `/etc/nyctala/restic.pass`. **Copy it off the
server** (password manager): without it the backups cannot be restored.

To check the chain against the off-site anchors from your own machine:

```bash
rclone cat nyctala-audit:nyctala-audit/siem-1 --include 'anchors-*' > anchors.ndjson
scp anchors.ndjson nyctala:/tmp/ && ssh -t nyctala \
  'cd /opt/nyctala/deploy && sudo docker compose run --rm -v /tmp/anchors.ndjson:/a.ndjson:ro detect integrity verify --anchors /a.ndjson'
```

## Everyday commands (on nyctala, in /opt/nyctala/deploy)

```bash
sudo docker compose exec detect nyctala alerts list
sudo docker compose exec detect nyctala alerts show <id>
sudo docker compose exec detect nyctala incidents
sudo docker compose exec detect nyctala health
sudo docker compose exec detect nyctala integrity verify --anchors /anchors/anchors.ndjson
sudo docker compose logs -f detect
```

## Tested

Before the first real deployment these pieces were exercised locally in
Debian 13 systemd containers: a full `bootstrap.sh` run (and a second,
idempotent one), key-only SSH with root and passwords refused, the compose
stack bound to the WireGuard address, a sensor over a real WireGuard tunnel
(ingest accepted, SIEM-to-sensor connections dropped, ingest and SSH closed
outside the tunnel), the off-site timer with `--immutable` and a
backup-and-restore cycle. The real VPS, the provider's Object Lock and Vector's
journald source on a real host were not part of that test.
