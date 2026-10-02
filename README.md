# Veyl backend

Self-hostable, no-log VPN server. Rent a cheap VPS, point a domain at it, run one script. Users then download the Veyl app, claim an account number with a password and connect.

## Features

- One-command install on Debian or Ubuntu
- Your own domain with automatic HTTPS (Caddy, Let's Encrypt)
- Account number plus password: no email, number stored as a hash, password stored as PBKDF2-HMAC-SHA256
- 5 devices per account, one client certificate each, enforced without logging connections
- Keys generated on the client; the server signs a certificate request and never sees a private key
- Instant revoke: the certificate is added to the CRL and the live session is killed
- IPv4 and IPv6 tunnel, server-side DNS with no query logging
- Hardened by default: firewall policy drop, swap off, no persistent logs
- One static Go binary using only the standard library, no database, one small JSON state file
- Serves the web client from the same domain

## Install

    curl -fsSL https://raw.githubusercontent.com/VeylVPN/backend/main/install.sh | sudo bash

The installer checks the system, installs OpenVPN, nftables, Unbound and Caddy, builds `veyl` from source with a checksum-verified Go toolchain, opens a minimal firewall (your SSH ports, 80, 443) and prints a one-time setup link. Finish setup in the browser. Options: `--domain`, `--email`, `--branch`, `--yes`, `--force`.

Running it again repairs and updates an existing server without touching keys, settings or accounts (`sudo veyl update` does the same). `sudo bash install.sh --uninstall [--purge]` removes Veyl; `/var/lib/veyl` is kept unless `--purge` is given.

Open ports: SSH, 80/tcp, 443/tcp, 1194/udp.

## Why OpenVPN

- Works over any network: it runs over UDP or TCP and can be moved to port 443 to pass restrictive firewalls
- Mature: more than twenty years of use, heavily reviewed, stock packages in every distribution
- Wide client support on Windows, macOS, Linux, iOS and Android, so users are never locked in
- Standard X.509 certificates give per-device identity and real revocation through a CRL
- Modern settings: TLS 1.2 or newer, AES-256-GCM or ChaCha20-Poly1305, EC P-256 certificates and a tls-crypt key that hides the server from unauthenticated scans

Veyl does not change OpenVPN. It is a small Go control plane (accounts, devices, certificates, CRL) around the stock server, plus its own client.

## Accounts, passwords and devices

- `veyl account new` creates an unclaimed account and prints a 16-digit number
- The first `POST /v1/register` with that number sets its password (at least 10 characters). A number can be claimed once
- With `VEYL_OPEN_REGISTRATION=1`, `POST /v1/register` without an account creates a new account and returns its number
- Every request carries the account and password; there are no sessions or tokens
- Bad account and bad password give the same 401. After 5 failures an account is locked for 60 seconds, doubling up to 15 minutes, answered with 429. The throttle lives in memory only
- Each device has its own EC P-256 key and certificate. The client sends a CSR; the server ignores its subject and sets the common name to a random 16 character device id
- Client certificates are valid for 2 years, the CA for 10 years
- A device stores an id, a name, the certificate serial and a creation time. Nothing about use

## What is and is not stored

Stored: SHA-256 of each account number, a salted PBKDF2 password hash, and per device an id, name, certificate serial and creation time, plus the list of revoked serials.

Never stored: source IPs, connection or last-seen times, traffic counters, DNS queries, private keys, access logs. Online status is read live from the OpenVPN management socket and held only in memory for the length of a request.

## How logging is prevented

- OpenVPN runs with `verb 0`, no `log`, no `status` file, no `ifconfig-pool-persist`, and output sent to null
- journald storage disabled, rsyslog disabled, sshd LogLevel QUIET
- control plane output sent to null, HTTP error log discarded, Caddy logging discarded
- conntrack accounting and timestamps disabled, no firewall log rules
- unbound runs with query logging off and answers the tunnel only
- swap disabled
- the management socket is reachable only by root and the veyl user; the real address field of the client list is never read

No software can prove a negative to your users. Run your own server, and the people who trust it are the people who trust you.

## Account management

    sudo veyl account new
    sudo veyl account delete <number>

Deleting an account revokes all of its certificates and disconnects its devices.

## API

JSON bodies, errors as `{"error":"message"}`, request body limit 8 KiB.

- `GET /v1/info` returns `{endpoint, port, proto}`
- `POST /v1/register` `{account, password}` claims an account, or with open registration creates one; returns `{account}`
- `POST /v1/devices` `{account, password}` returns `{limit, devices:[{id, name, created, online}]}`
- `POST /v1/enroll` `{account, password, name, csr}` returns `{id, profile}`; 409 when the device limit is reached. The profile is a full `.ovpn` file whose key block contains the line `__PRIVATE_KEY__` for the client to replace with its own PEM private key
- `POST /v1/revoke` `{account, password, id}` returns `{status:"revoked"}`
- `POST /v1/password` `{account, password, new_password}` returns `{status:"changed"}`

Status codes: 400 bad input, 401 invalid credentials, 404 unknown device, 409 conflict, 429 throttled, 500 server error.

## Configuration

`veyld` flags, each with an environment variable: `-data` (`VEYL_DATA`, default `/var/lib/veyl`), `-listen` (`VEYL_LISTEN`), `-endpoint` (`VEYL_ENDPOINT`), `-static` (`VEYL_STATIC`), `-mgmt` (`VEYL_MGMT`, default `/run/veyl/mgmt`). `veyld init [dir]` creates the CA, server certificate, tls-crypt key and empty CRL.
