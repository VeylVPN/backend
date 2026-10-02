# Veyl public API

The public API of a Veyl server lives under `https://<your-server>/v1/`. It lets the Veyl apps, and anything else you write, sign in with an account number and password, enroll devices and manage the account. The machine-readable description is served by every server at `GET /v1/openapi.yaml` (OpenAPI 3.1) and lives in this repository at `docs/openapi.yaml`.

The admin panel (`/v1/admin/*`) and the setup wizard (`/v1/setup/*`) are separate and not covered here.

## Basics

- JSON in, JSON out. Send `Content-Type: application/json` with every request that has a body; anything else gets `415 UNSUPPORTED_MEDIA_TYPE`.
- Request bodies are limited to 8 KiB.
- The newer endpoints (`/v1/auth/*`, `/v1/me*`) reject unknown fields and trailing data with `400 BAD_REQUEST`.
- Times in the newer endpoints are RFC 3339 in UTC. Creation times are rounded to the day on purpose.
- The account number never appears in a URL.
- Every response carries `Cache-Control: no-store`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, a deny-all `Content-Security-Policy`, `Cross-Origin-Opener-Policy: same-origin` and `Permissions-Policy`. Behind the TLS proxy (`X-Forwarded-Proto: https`) responses also carry `Strict-Transport-Security`.

In the examples below:

```sh
export VEYL=https://vpn.example.com
```

## Errors

Every error has the same envelope:

```json
{"error": "device limit reached", "code": "MAX_DEVICES_REACHED"}
```

Branch on `code`. The `error` text is for people and may change.

| Code | Status | Meaning |
| --- | --- | --- |
| `INVALID_CREDENTIALS` | 401 | Wrong account number or password. Identical for both, on purpose |
| `INVALID_ACCESS_TOKEN` | 401 | Bearer token missing, malformed, expired or revoked. Sign in again |
| `ACCOUNT_DISABLED` | 403 | The administrator disabled the account |
| `ACCOUNT_EXPIRED` | 403 | The account is past its expiry date. It can still sign in and read `/v1/me` |
| `ACCOUNT_ALREADY_CLAIMED` | 409 | The account number already has a password |
| `MAX_DEVICES_REACHED` | 409 | Revoke a device first |
| `DEVICE_NOT_FOUND` | 404 | No such device on this account |
| `INVALID_INVITE` | 403 | Invite unknown, used up or expired |
| `REGISTRATION_CLOSED` | 400 or 403 | This server only accepts account numbers made by its administrator |
| `INVITE_REQUIRED` | 400 | This server needs an account number or an invite |
| `WEAK_PASSWORD` | 400 | Passwords are 10 to 256 characters |
| `INVALID_DEVICE_NAME` | 400 | Names are 1 to 32 printable characters |
| `INVALID_CSR` | 400 | Send a PEM PKCS#10 request for an EC P-256 key |
| `INVALID_DNS_CATEGORY` | 400 | Unknown or repeated DNS blocking category |
| `BAD_REQUEST` | 400 | Malformed JSON, unknown field or missing field |
| `PAYLOAD_TOO_LARGE` | 413 | Body over 8 KiB (400 on the legacy endpoints) |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Body not sent as `application/json` |
| `TOO_MANY_REQUESTS` | 429 | Slow down. See `Retry-After` |
| `NOT_CONFIGURED` | 503 | The server has no public address yet |
| `NOT_FOUND`, `METHOD_NOT_ALLOWED` | 404, 405 | No such endpoint or method |
| `INTERNAL_ERROR` | 500 | Something failed on the server |

## Rate limits

- Every endpoint: 120 requests per minute per client address, under a global ceiling.
- Every endpoint that checks a password (`/v1/auth/token`, `/v1/register`, `/v1/devices`, `/v1/enroll`, `/v1/revoke`, `/v1/password`, `PUT /v1/me/password`, `DELETE /v1/me`) shares one stricter policy: 10 per minute per client address with a burst of 20, under a global ceiling of 300 per minute.
- Separately, 5 wrong passwords lock that account for 60 seconds, doubling up to 15 minutes, whatever address they come from.

Limits live in memory only. Client addresses are keyed through HMAC with a random key generated at start, IPv6 addresses are grouped by /64, idle entries are pruned, and nothing is logged. Requests that arrive through OpenVPN's stealth port sharing all appear to come from the server itself; they share the global ceiling and the per-account lockout still applies.

## Server

### `GET /v1/info`

```sh
curl -s $VEYL/v1/info
```

```json
{
  "endpoint": "vpn.example.com",
  "port": 1194,
  "proto": "udp",
  "stealth": true,
  "stealth_port": 443,
  "platform": "linux",
  "name": "Veyl",
  "version": "0.2.0",
  "registration": "invite",
  "device_limit": 5,
  "dns_categories": ["ads", "trackers", "malware", "adult", "gambling", "social"],
  "dns_default": ["ads", "trackers", "malware"],
  "post_quantum": true,
  "app_url": "https://github.com/VeylVPN/frontend/releases/latest"
}
```

`registration` is `closed` (only numbers made by the administrator), `invite` (those, or an invite code) or `open` (anyone). `post_quantum` is what the operator asked for; the hybrid key exchange is only used when the server's OpenSSL supports it.

### `GET /v1/health`

```sh
curl -s $VEYL/v1/health
```

```json
{"status": "ok"}
```

### `GET /v1/openapi.yaml`

```sh
curl -s $VEYL/v1/openapi.yaml
```

## Getting an account

### `POST /v1/register`

Claim an account number made by the administrator by giving it a password:

```sh
curl -s $VEYL/v1/register -H 'Content-Type: application/json' \
  -d '{"account":"1234567812345678","password":"a long passphrase"}'
```

Redeem an invite (servers in `invite` or `open` mode):

```sh
curl -s $VEYL/v1/register -H 'Content-Type: application/json' \
  -d '{"invite":"VEYL-ABCD-EFGH-IJKL-MNOP","password":"a long passphrase"}'
```

Create a new account (servers in `open` mode):

```sh
curl -s $VEYL/v1/register -H 'Content-Type: application/json' \
  -d '{"password":"a long passphrase"}'
```

Each returns the account number. It is the only identifier the account has, so write it down:

```json
{"account": "1234567812345678"}
```

## Access tokens

### `POST /v1/auth/token`

```sh
curl -s $VEYL/v1/auth/token -H 'Content-Type: application/json' \
  -d '{"account":"1234567812345678","password":"a long passphrase"}'
```

```json
{"access_token": "vey_4mB0rjX3c7r7m3eT1JpZp0iF0Jp8rWJb1o2vO3c9rJk", "expires_at": "2026-10-02T13:00:00Z"}
```

Use it as `Authorization: Bearer <token>`:

```sh
export TOKEN=vey_4mB0rjX3c7r7m3eT1JpZp0iF0Jp8rWJb1o2vO3c9rJk
```

How tokens behave:

- `vey_` followed by 43 base64url characters, 256 random bits.
- Valid for one hour. Sign in again when you get `INVALID_ACCESS_TOKEN`.
- Kept in server memory only, as SHA-256 hashes. A restart signs everyone out.
- At most 10 live tokens per account; the 11th evicts the oldest.
- Revoked on logout, password change (through either password endpoint), account deletion and account disablement. Disabling answers the next request with `ACCOUNT_DISABLED` and every later one with `INVALID_ACCESS_TOKEN`.

### `POST /v1/auth/logout`

```sh
curl -s -X POST $VEYL/v1/auth/logout -H "Authorization: Bearer $TOKEN"
```

Returns `204`.

## Your account

### `GET /v1/me`

```sh
curl -s $VEYL/v1/me -H "Authorization: Bearer $TOKEN"
```

```json
{
  "id": "3f9a1c2b7d4e",
  "created": "2026-09-14T00:00:00Z",
  "expires": null,
  "device_limit": 5,
  "devices": 2,
  "dns_blocking": ["ads", "trackers", "malware"],
  "dns_custom": false,
  "status": "active"
}
```

`id` is an opaque ID, not the account number. `status` is `active`, `expired` or `disabled`.

### `PUT /v1/me/dns`

Choose which content to block in DNS for every device of the account. An empty list turns blocking off.

```sh
curl -s -X PUT $VEYL/v1/me/dns -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"blocking":["ads","trackers","social"]}'
```

```json
{"dns_blocking": ["ads", "trackers", "social"], "dns_custom": true}
```

Categories: `ads`, `trackers`, `malware`, `adult`, `gambling`, `social`. A device picks up the change on its next connection.

### `DELETE /v1/me/dns`

Go back to the server default.

```sh
curl -s -X DELETE $VEYL/v1/me/dns -H "Authorization: Bearer $TOKEN"
```

### `PUT /v1/me/password`

```sh
curl -s -X PUT $VEYL/v1/me/password -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"password":"a long passphrase","new_password":"an even longer passphrase"}'
```

Every token of the account stops working, including the one you used. The response carries a fresh one in the same shape as `POST /v1/auth/token`.

### `DELETE /v1/me`

Deletes the account and revokes all its devices. Asks for the password again.

```sh
curl -s -X DELETE $VEYL/v1/me -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"password":"a long passphrase"}'
```

Returns `204`.

## Devices

Every device has its own key pair, generated on the device. The server only ever sees a certificate request, signs it with a random device ID as the common name, and wraps a per-device tls-crypt-v2 key around that same ID.

### `GET /v1/me/devices`

```sh
curl -s $VEYL/v1/me/devices -H "Authorization: Bearer $TOKEN"
```

```json
{
  "limit": 5,
  "devices": [
    {"id": "9c1e0b7f4a2d6e83", "name": "Quiet Otter", "created": "2026-09-14T00:00:00Z", "online": true}
  ]
}
```

`online` is read live from OpenVPN for this request and never stored.

### `POST /v1/me/devices`

```sh
openssl ecparam -name prime256v1 -genkey -noout -out device.key
openssl req -new -key device.key -subj /CN=device -out device.csr
jq -n --rawfile csr device.csr '{name:"Laptop", csr:$csr}' |
  curl -s $VEYL/v1/me/devices -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d @- > device.json
```

```json
{"id": "9c1e0b7f4a2d6e83", "name": "Laptop", "profile": "client\ndev tun\n..."}
```

Leave `name` out or empty and the server picks a friendly one such as `Quiet Otter`, unique within the account. The CSR subject is ignored.

The profile is a complete OpenVPN client configuration except for the private key, which appears as the literal `__PRIVATE_KEY__`. Put your key in its place:

```sh
jq -r .profile device.json | awk -v key="$(cat device.key)" '{ if ($0 == "__PRIVATE_KEY__") print key; else print }' > veyl.ovpn
sudo openvpn --config veyl.ovpn
```

What the profile contains:

- `remote <host> <udp port> udp` and, when the server has stealth on, `remote <host> <stealth port> tcp-client` as a fallback for networks that block VPNs (443 on Linux, 993 by default on Windows)
- `connect-retry 2 5`, `server-poll-timeout 4`, `resolv-retry infinite`, `nobind`, `persist-key`, `persist-tun`
- `remote-cert-tls server`, `verify-x509-name veyl-server name`, `tls-version-min 1.2`
- `data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM`, with no `data-ciphers-fallback` so kernel data channel offload keeps working
- `auth-nocache`, `setenv opt block-outside-dns`, `verb 1`
- `<ca>`, `<cert>`, `<key>` and the per-device `<tls-crypt-v2>` key

Devices enrolled before tls-crypt-v2 carry a `<tls-crypt>` key and must be enrolled again.

### `PATCH /v1/me/devices/{id}`

```sh
curl -s -X PATCH $VEYL/v1/me/devices/9c1e0b7f4a2d6e83 -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"Work laptop"}'
```

Returns the device.

### `DELETE /v1/me/devices/{id}`

```sh
curl -s -X DELETE $VEYL/v1/me/devices/9c1e0b7f4a2d6e83 -H "Authorization: Bearer $TOKEN"
```

Returns `204`. The certificate goes on the CRL, the live session is closed on every OpenVPN instance, and the device's tls-crypt-v2 key is refused from then on, before any TLS happens.

## Legacy endpoints

The first Veyl apps send the account number and password in every request body. These endpoints keep exactly their original request and response shapes; error bodies gained a `code` field.

```sh
curl -s $VEYL/v1/devices -H 'Content-Type: application/json' \
  -d '{"account":"1234567812345678","password":"a long passphrase"}'
```

| Endpoint | Body | Response |
| --- | --- | --- |
| `POST /v1/devices` | `account, password` | `{limit, devices:[{id, name, created, online}]}` with `created` in Unix seconds |
| `POST /v1/enroll` | `account, password, name, csr` | `{id, profile}`; `name` is required here |
| `POST /v1/revoke` | `account, password, id` | `{"status":"revoked"}` |
| `POST /v1/password` | `account, password, new_password` | `{"status":"changed"}`, and every token of the account is revoked |

New code should use tokens.

## How a connection is checked

OpenVPN asks Veyl twice before letting a device in, over a unix socket only `veyl` and OpenVPN can reach (`/run/veyl/hook.sock`, mode 0660, group `veyl`):

1. `tls-crypt-v2-verify "/usr/local/bin/veyl hook verify"` runs on the very first packet, before TLS. OpenVPN 2.6 sets `metadata_type=0` for user metadata and writes the raw metadata bytes (the device ID, not base64) to the file named in `metadata_file`. The device must exist and its account must be active. Keys with timestamp metadata (`metadata_type=1`), unknown IDs or malformed metadata are refused.
2. `client-connect "/usr/local/bin/veyl hook connect"` runs after TLS with the certificate's `common_name`. The same check runs again, and on success the hook writes `push "dhcp-option DNS 10.64.0.N"` for the account's blocking choice.

Both fail closed: no answer within 5 seconds, an unreadable state file or anything unexpected means the device is refused. The hook never reads `untrusted_ip`, `trusted_ip` or any other address variable that OpenVPN sets.
