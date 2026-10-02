# Veyl backend

Self-hostable, no-log WireGuard VPN for a single cheap VPS (Debian/Ubuntu).

## Install

    git clone https://github.com/veylvpn/backend && cd backend
    sudo deploy/install.sh <server-ip-or-domain> [path-to-frontend-dist]
    sudo veyl account new

The account number is the only credential. It is stored hashed and cannot be recovered. Each account may register 5 devices.

## What is and is not stored

Stored: SHA-256 of each account number, and per device a public key and an internal address.

Never stored: source IPs, handshake or last-seen times, traffic counters, DNS queries, connection times, private keys, access logs.

## How logging is prevented

- journald storage disabled, rsyslog disabled, sshd LogLevel QUIET
- control plane stdout/stderr sent to null, HTTP server error log discarded
- conntrack accounting and timestamps disabled, no nftables log rules
- unbound runs with query logging off, reachable from the tunnel only
- swap disabled
- peers idle for over 10 minutes are removed and re-added so WireGuard drops the remembered client endpoint; handshake times are read in memory only and never persisted

## API

- `POST /v1/enroll` `{account, public_key}` returns tunnel addresses, server key, endpoint, DNS
- `POST /v1/devices` `{account}`
- `POST /v1/revoke` `{account, public_key}`

Clients generate their own keys; the server never sees a private key. Put the API behind TLS (Caddy or similar with access logs off) before exposing it publicly.
