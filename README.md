# Veyl backend

Self-hostable, no-log VPN server. Rent a cheap VPS, point a domain at it, run one script. Users then download the Veyl app and connect with an account number.

## Features

- One-command install on Debian or Ubuntu
- Your own domain with automatic HTTPS (Caddy, Let's Encrypt)
- Account numbers only: no email, no password, stored as a hash
- 5 devices per account, enforced without logging connections
- Keys generated on the client; the server never sees a private key
- IPv4 and IPv6 tunnel, server-side DNS with no query logging
- Hardened by default: firewall policy drop, swap off, no persistent logs
- Single static Go binary, no database, one small JSON state file
- Serves the web client from the same domain

## Install

    git clone https://github.com/veylvpn/backend && cd backend
    sudo deploy/install.sh vpn.example.com [path-to-frontend-dist]
    sudo veyl account new

Point an A record for `vpn.example.com` at the VPS first. Without a domain, pass the public IP; the API then runs over plain HTTP and a domain is strongly recommended.

Open ports: 22/tcp, 80/tcp, 443/tcp, 51820/udp.

## Why WireGuard

- About 4,000 lines of code against hundreds of thousands for OpenVPN or IPsec, so it can be read and audited
- Fixed modern crypto (Noise handshake, Curve25519, ChaCha20-Poly1305, BLAKE2s) with no cipher negotiation, so no downgrade attacks
- In the Linux kernel, fast and cheap on CPU, which suits small VPSs
- Stateless from the outside: silent to unauthenticated packets
- Official Windows, macOS, Linux, iOS and Android clients exist, so users are never locked in

Known privacy edges, and how Veyl handles them:

- WireGuard remembers each peer's last endpoint IP in RAM. Veyl removes and re-adds peers idle for 10 minutes, and never reads or stores endpoints.
- Peers have static tunnel addresses. Veyl stores them only against a public key, never against traffic.

## Why not fork an existing VPN

- Mullvad's app is GPL-3.0 and built around Mullvad's own private API; repointing it means reimplementing that API and rebranding everything
- Headscale, NetBird, Netmaker and Firezone are mesh and SSO products with licence terms that make them a poor base
- wg-easy has no accounts and no client
- Writing our own VPN protocol would be a security mistake; WireGuard is the right primitive

So Veyl is a small control plane (about 500 lines of Go) on top of stock WireGuard, plus its own client.

## What is and is not stored

Stored: SHA-256 of each account number, and per device a public key and an internal address.

Never stored: source IPs, handshake or last-seen times, traffic counters, DNS queries, connection times, private keys, access logs.

## How logging is prevented

- journald storage disabled, rsyslog disabled, sshd LogLevel QUIET
- control plane output sent to null, HTTP error log discarded, Caddy logging discarded
- conntrack accounting and timestamps disabled, no firewall log rules
- unbound runs with query logging off and answers the tunnel only
- swap disabled
- idle peers flushed so WireGuard forgets client endpoints; handshake times are read in memory only

No software can prove a negative to your users. Run your own server, and the people who trust it are the people who trust you.

## Account management

    sudo veyl account new
    sudo veyl account delete <number>

## API

- `POST /v1/enroll` `{account, public_key}`
- `POST /v1/devices` `{account}`
- `POST /v1/revoke` `{account, public_key}`
