# Linux VPS Deployment Validation

ProcSentry is intended to run on Ubuntu/Debian VPS hosts with access to the host
PID namespace, `/proc`, cgroups, and socket ownership metadata.

## Minimal VPS Sizing

- 1 vCPU, 512 MB RAM: usable for small hosts with `scan_interval: 10`
- 1 vCPU, 1 GB RAM: recommended minimum
- 2 vCPU, 2 GB RAM: comfortable for busy self-hosting boxes

Target overhead after warmup: under 100 MB RSS and low single-digit CPU while
idle. Use the benchmark command below on the target host.

## Ubuntu/Debian Install

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv sqlite3
sudo mkdir -p /opt/procsentry /var/lib/procsentry
sudo cp -a . /opt/procsentry
cd /opt/procsentry
sudo bash scripts/install.sh
```

Dashboard:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/capabilities
```

The dashboard binds to `127.0.0.1` by default. Keep that default for direct VPS
installs and expose it through SSH forwarding or a reverse proxy with
authentication.

SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 root@your-vps
```

Built-in authentication can be enabled with environment variables:

```bash
export PROCSENTRY_WEB__AUTH_ENABLED=true
export PROCSENTRY_WEB__AUTH_USERNAME=admin
export PROCSENTRY_WEB__AUTH_PASSWORD='replace-with-long-password'
export PROCSENTRY_WEB__SESSION_SECRET='replace-with-long-random-secret'
```

For nginx, proxy only from an authenticated vhost:

```nginx
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Capability Diagnostics

```bash
procsentry --config /etc/procsentry.yml scan-once
curl -s http://127.0.0.1:8080/health/score | python3 -m json.tool
curl -s http://127.0.0.1:8080/metrics | python3 -m json.tool
```

Expected Linux production capabilities:

- `supports_procfs: true`
- `supports_cgroups: true`
- `supports_deleted_exe: true`
- `supports_zombie_state: true`

Systemd may be false inside minimal containers; that is degraded but not fatal.

## Live Linux Benchmark

```bash
python scripts/benchmark_scan.py --iterations 20 --sleep 1
```

Important fields:

- `scan_ms_first`: cold scan cost
- `scan_ms_warm_avg`: debounced/warm cost
- `last_collect_ms`: psutil process collection
- `last_ports_ms`: port attachment stage
- `last_socket_enum_ms`: socket enumeration cost
- `last_enrich_ms`: procfs/cgroup/systemd enrichment
- `last_fingerprint_ms`: fingerprint generation/cache

If `last_socket_enum_ms` dominates, run as root and check host connection count:

```bash
ss -tunap | wc -l
```

## Troubleshooting

Service status:

```bash
sudo systemctl status procsentry
sudo journalctl -u procsentry -n 100 --no-pager
```

Database size:

```bash
du -h /var/lib/procsentry/procsentry.db*
sqlite3 /var/lib/procsentry/procsentry.db 'PRAGMA integrity_check;'
```

Socket ownership:

```bash
sudo ss -tulpn
```

Permission symptoms:

- missing ports: run agent as root
- missing other users' processes: run agent as root
- degraded cgroups: verify `/proc/self/cgroup` and `/sys/fs/cgroup`

## Production Recommendations

- Keep `scan_interval` at `5` or higher on small VPSes.
- Keep dashboard bound to localhost unless built-in auth or reverse-proxy auth is enabled.
- Put the dashboard behind a reverse proxy with authentication for remote access.
- Keep auto-healing disabled until alerts are reviewed over several days.
- Review duplicate groups before killing processes.
