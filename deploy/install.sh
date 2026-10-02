#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

HOST="${1:-}"
STATIC_DIR="${2:-}"
[ -n "$HOST" ] || { echo "usage: install.sh <domain-or-public-ip> [frontend-dist]"; exit 1; }
if echo "$HOST" | grep -Eq '^[0-9.]+$|:'; then USE_TLS=0; else USE_TLS=1; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
WAN="$(ip -o -4 route show to default | awk '{print $5; exit}')"

apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn nftables unbound golang-go ca-certificates
if [ "$USE_TLS" -eq 1 ]; then DEBIAN_FRONTEND=noninteractive apt-get install -y caddy; fi

( cd "$ROOT" && go build -trimpath -ldflags="-s -w" -o /usr/local/bin/veyld ./cmd/veyld )

id veyl >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin veyl

install -d -m 700 /etc/veyl
install -d -m 755 -o veyl -g veyl /var/lib/veyl

/usr/local/bin/veyld -data /var/lib/veyl init
chown -R veyl:veyl /var/lib/veyl
chmod 755 /var/lib/veyl

install -m 644 "$HERE/server.conf" /etc/veyl/server.conf
install -m 644 "$HERE/veyl-openvpn.service" /etc/systemd/system/veyl-openvpn.service

install -m 644 "$HERE/sysctl-veyl.conf" /etc/sysctl.d/99-veyl.conf
modprobe nf_conntrack || true
sysctl --system >/dev/null

install -d /etc/systemd/journald.conf.d
install -m 644 "$HERE/journald-nolog.conf" /etc/systemd/journald.conf.d/nolog.conf
systemctl restart systemd-journald
systemctl disable --now rsyslog 2>/dev/null || true
rm -rf /var/log/journal
swapoff -a || true
sed -i '/\sswap\s/d' /etc/fstab

grep -q '^LogLevel QUIET' /etc/ssh/sshd_config || echo 'LogLevel QUIET' >> /etc/ssh/sshd_config
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

cat > /etc/nftables.conf <<NFT
#!/usr/sbin/nft -f
flush ruleset

table inet veyl {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    tcp dport 22 accept
    udp dport 1194 accept
    tcp dport { 80, 443 } accept
    iifname "tun*" udp dport 53 accept
    iifname "tun*" tcp dport 53 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "tun*" oifname "$WAN" accept
  }
}

table ip veyl_nat {
  chain post {
    type nat hook postrouting priority 100;
    oifname "$WAN" ip saddr 10.8.0.0/24 masquerade
  }
}

table ip6 veyl_nat6 {
  chain post {
    type nat hook postrouting priority 100;
    oifname "$WAN" ip6 saddr fd88:88:88::/64 masquerade
  }
}
NFT
systemctl enable --now nftables

install -m 644 "$HERE/unbound-veyl.conf" /etc/unbound/unbound.conf.d/veyl.conf
systemctl enable unbound

systemctl daemon-reload
systemctl enable --now veyl-openvpn
systemctl restart unbound

if [ -n "$STATIC_DIR" ]; then
  install -d /opt/veyl/web
  cp -r "$STATIC_DIR"/. /opt/veyl/web/
fi

if [ "$USE_TLS" -eq 1 ]; then
  LISTEN="127.0.0.1:8080"
  cat > /etc/caddy/Caddyfile <<CADDY
{
  admin off
  log {
    output discard
  }
}

$HOST {
  reverse_proxy 127.0.0.1:8080
}
CADDY
  systemctl enable caddy
  systemctl restart caddy
else
  LISTEN="0.0.0.0:80"
  echo "No domain given: the API is served over plain HTTP. Use a domain for HTTPS."
fi

cat > /etc/veyl/env <<ENVF
VEYL_ENDPOINT=$HOST
VEYL_LISTEN=$LISTEN
VEYL_STATIC=/opt/veyl/web
VEYL_DATA=/var/lib/veyl
VEYL_MGMT=/run/veyl/mgmt
ENVF
chmod 600 /etc/veyl/env

install -m 644 "$HERE/veyld.service" /etc/systemd/system/veyld.service
cat > /usr/local/bin/veyl <<'WRAP'
#!/bin/sh
exec setpriv --reuid=veyl --regid=veyl --init-groups env VEYL_DATA=/var/lib/veyl VEYL_MGMT=/run/veyl/mgmt /usr/local/bin/veyld "$@"
WRAP
chmod 755 /usr/local/bin/veyl
systemctl daemon-reload
systemctl enable --now veyld

echo
echo "Create an account number with:  veyl account new"
