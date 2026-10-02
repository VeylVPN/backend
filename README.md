# Veyl server

A self-hosted, no-log VPN server for a cheap VPS. One command installs everything, then a short setup page in your browser finishes the job. Nothing to configure by hand.

## Install

Rent a VPS running Debian 12/13 or Ubuntu 22.04/24.04 (1 vCPU and 512 MB RAM is enough), connect with SSH and run:

    curl -fsSL https://raw.githubusercontent.com/VeylVPN/backend/main/install.sh | sudo bash

The installer checks the machine, installs OpenVPN, Unbound, Caddy and nftables, builds `veyl` from source with a checksum-verified Go toolchain, opens a minimal firewall (your SSH ports, 80 and 443) and prints a link:

    Open this link to finish setup:
      http://203.0.113.5/setup#<one-time token>

Open it and answer a few questions:

1. **Address**: use your own domain, or one click for a free `203-0-113-5.sslip.io` name. The server gets a real HTTPS certificate before you type any password.
2. **Admin password** for the admin panel.
3. **VPN**: server name, stealth mode, IPv6, post-quantum, devices per account.
4. **Privacy**: what to block by default (ads, trackers, malware, adult, gambling, social media), how the server looks up names, automatic security updates.
5. **Accounts**: invite-only, open, or only accounts you create, plus your own first account.

Press install and watch every step go green. You get your account number, the address to type into the Veyl app, a link to the admin panel and an encrypted backup. The setup page then locks itself.

Lost the link? `sudo veyl setup-link`. Re-running the installer repairs and updates without touching keys, settings or accounts.

## Features

**Accounts like Mullvad.** A random 16-digit account number and a password, no email. Numbers are stored only as SHA-256 hashes, passwords as PBKDF2-SHA256 (600k iterations). Admins see accounts by a short ID and label, never the number. Accounts can expire, be paused and be limited to a number of devices; invite codes let people join without you sharing anything else.

**Devices you can see and remove.** Each device has its own certificate made from a key generated on the device, and its own `tls-crypt-v2` key. Devices get friendly names like "Steady Ibis". Removing or pausing takes effect instantly: the certificate is revoked, the live session is killed, and the device is turned away before TLS even starts.

**Content blocking per account.** A built-in DNS resolver blocks ads, trackers, malware, adult content, gambling and social media using HaGeZi and Mullvad blocklists, refreshed daily. Like Mullvad's resolvers, each combination lives on its own address and every account gets the right one pushed when it connects. Blocklists are stored as 8-byte hashes, so all six categories (about 770,000 domains) take roughly 6 MB of memory. Names are resolved privately by Unbound, or over encrypted DNS through Quad9, Cloudflare or Mullvad.

**Works on hostile networks.** Stealth mode runs a second OpenVPN instance on TCP 443 that shares the port with the HTTPS site, so the VPN looks like normal web traffic. Apps try UDP first and fall back automatically.

**Post-quantum key exchange** (hybrid X25519 + ML-KEM-768) is switched on automatically when the server's OpenSSL is 3.5 or newer (Debian 13).

**Admin panel** with live connected count, accounts, devices, invites, settings, service health, blocklist status, two-factor authentication and encrypted backups.

**API** for apps and scripts: Mullvad-style access tokens, device management and DNS preferences. See [docs/API.md](docs/API.md) and [docs/openapi.yaml](docs/openapi.yaml).

## No logs

Veyl stores account hashes, password hashes, device public certificate data and settings. It never stores IP addresses, connection times, traffic amounts or DNS queries, and the server is set up so nothing else does either:

- journald keeps nothing on disk, rsyslog is disabled, login records (`wtmp`, `btmp`, `lastlog`) point to `/dev/null`, cloud-init logs are removed, core dumps and swap are off, SSH logs quietly
- OpenVPN runs with `verb 0` and no status or log file; the distro unit's status file is removed
- Caddy discards all logs; the API, DNS front and hook never log requests
- connection tracking accounting is off and the firewall has no log rules
- creation dates are rounded to the day
- "online now" comes live from OpenVPN's memory and is never written down

Being honest about limits: this runs on a rented VPS, not on RAM-only hardware like Mullvad's, so the hosting company could still image the machine or watch its network. You decide who to trust.

## Security design

Privilege separation, the same idea Mullvad uses between its app and daemon:

| Process | Runs as | Does |
| --- | --- | --- |
| `veyl serve` | `veyl` | API, admin panel, setup page, connection hook |
| `veyl agent` | root | only fixed, validated system operations over a peer-checked unix socket |
| `veyl dns` | `veyl` with port-53 capability only | content-blocking DNS front |
| OpenVPN | drops to `veyl-ovpn` | the tunnels; asks `veyl hook` before letting a device in |

- Every setting is validated before it can reach a root-owned config file, and configs are rendered from fixed templates, so a setting cannot inject a line into the OpenVPN or firewall config.
- Unknown, revoked or paused devices are rejected by `tls-crypt-v2-verify` before the TLS handshake, and `force-cookie` keeps the handshake stateless against floods.
- The management socket only accepts the `veyl` group; the hook fails closed.
- Rate limits are identical on every sign-in path, with per-account lockouts that keep working when stealth mode hides client addresses.
- Input lengths are capped everywhere, and account numbers never appear in URLs.
- The setup link uses a one-time token in the URL fragment (never sent over the network or logged), and setup locks itself when finished.
- The admin panel uses HttpOnly SameSite cookies, CSRF tokens, sign-in throttling and optional TOTP, and can be hidden from the internet so it only answers through the VPN.
- The firewall only replaces Veyl's own tables, and SSH ports are detected before it is enabled.

## Commands

    sudo veyl status                          service health
    sudo veyl setup-link                      fresh setup link
    sudo veyl account new [-label L] [-expires-days N] [-password]
    sudo veyl account list
    sudo veyl account delete <number|id>
    sudo veyl invite new [-uses N] [-days N]
    sudo veyl admin reset-password
    sudo veyl backup <file>
    sudo veyl restore [-force] <file>
    sudo veyl update
    sudo veyl uninstall [-purge]

## Why OpenVPN

It runs over UDP or TCP, so it gets through networks that block other VPNs, and every platform has a mature client. Note that Mullvad itself retired OpenVPN in January 2026 to focus on WireGuard, which is faster and simpler; Veyl uses OpenVPN for reach and compatibility, hardened with tls-crypt-v2, per-device certificates and post-quantum key exchange where available.

## Development

    go test ./...
    VEYL_REAL_OPENVPN=1 go test -run TestRealOpenVPN ./internal/hook

The second command runs a real OpenVPN server and clients against the hook. Standard library only.

## Layout

    cmd/veyl            the single binary
    internal/api        public API, tokens, enrollment
    internal/admin      admin panel API, sessions, TOTP
    internal/setup      first-run wizard
    internal/web        embedded UI
    internal/agent      root helper
    internal/render     config templates
    internal/dns        content-blocking DNS front
    internal/hook       OpenVPN connection hook
    internal/store      accounts, devices, invites
    internal/pki        CA, certificates, CRL, tls-crypt-v2
    internal/backup     encrypted backups
    install.sh          the installer
