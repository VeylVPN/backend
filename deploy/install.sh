#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

ENDPOINT="${1:-}"
STATIC_DIR="${2:-}"
[ -n "$ENDPOINT" ] || { echo "usage: install.sh <public-ip-or-domain>[:51820] [static-dir]"; exit 1; }
case "$ENDPOINT" in *:*) ;; *) ENDPOINT="$ENDPOINT:51820" ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
WAN="$(ip -o -4 route show to default | awk '{print $5; exit}')"

apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools nftables unbound golang-go ca-certificates

( cd "$ROOT" && go build -trimpath -ldflags="-s -w" -o /usr/local/bin/veyld ./cmd/veyld )

id veyl >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin veyl

install -d -m 700 /etc/wireguard /etc/veyl
install -d -m 700 -o veyl -g veyl /var/lib/veyl

if [ ! -f /etc/wireguard/wg0.key ]; then
  umask 077
  wg genkey > /etc/wireguard/wg0.key
fi

cat > /etc/wireguard/wg0.conf <<WG
[Interface]
Address = 10.66.0.1/24, fd66:66:66::1/64
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/wg0.key)
MTU = 1380
WG
chmod 600 /etc/wireguard/wg0.conf

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
    udp dport 51820 accept
    tcp dport { 80, 443 } accept
    iifname "wg0" udp dport 53 accept
    iifname "wg0" tcp dport 53 accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" oifname "$WAN" accept
  }
}

table ip veyl_nat {
  chain post {
    type nat hook postrouting priority 100;
    oifname "$WAN" ip saddr 10.66.0.0/24 masquerade
  }
}

table ip6 veyl_nat6 {
  chain post {
    type nat hook postrouting priority 100;
    oifname "$WAN" ip6 saddr fd66:66:66::/64 masquerade
  }
}
NFT
systemctl enable --now nftables

install -m 644 "$HERE/unbound-veyl.conf" /etc/unbound/unbound.conf.d/veyl.conf
systemctl enable unbound

systemctl enable --now wg-quick@wg0
systemctl restart unbound

if [ -n "$STATIC_DIR" ]; then
  install -d /opt/veyl/web
  cp -r "$STATIC_DIR"/. /opt/veyl/web/
fi

cat > /etc/veyl/env <<ENVF
VEYL_ENDPOINT=$ENDPOINT
VEYL_LISTEN=0.0.0.0:80
VEYL_STATIC=/opt/veyl/web
ENVF
chmod 600 /etc/veyl/env

install -m 644 "$HERE/veyld.service" /etc/systemd/system/veyld.service
cat > /usr/local/bin/veyl <<'WRAP'
#!/bin/sh
exec setpriv --reuid=veyl --regid=veyl --init-groups --inh-caps=+net_admin --ambient-caps=+net_admin env VEYL_DATA=/var/lib/veyl/state.json /usr/local/bin/veyld "$@"
WRAP
chmod 755 /usr/local/bin/veyl
systemctl daemon-reload
systemctl enable --now veyld

echo
echo "Create an account number with:  veyl account new"
