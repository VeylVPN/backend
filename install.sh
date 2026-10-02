#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/VeylVPN/backend.git"
REPO_SLUG="VeylVPN/backend"
RELEASES="https://github.com/VeylVPN/backend/releases/download"
SRC_DIR="/opt/veyl/src"
BUILD_DIR="/opt/veyl/build"
BIN="/usr/local/bin/veyl"
DATA_DIR="/var/lib/veyl"
PANEL_DIR="/var/lib/veyl-panel"
LOG="/run/veyl-install.log"
SWAPFILE="/var/lib/veyl-build.swap"
MODULE="github.com/veylvpn/backend"

DOMAIN=""
EMAIL=""
BRANCH="main"
BRANCH_SET=0
VERSION=""
FORCE_BUILD=0
RELEASE=""
ASSUME_YES=0
FORCE=0
UNINSTALL=0
PURGE=0
PANEL=0
PANEL_ONLY=0
PANEL_DOMAIN=""
ARCH=""
TEMP_SWAP=0
SELF_SUM=""
STARTED=0

say() {
	printf '%s\n' "$*"
}

step() {
	printf '\033[1m==>\033[0m %s\n' "$*"
}

die() {
	printf '\033[31mError:\033[0m %s\n' "$*" >&2
	fail 1
}

fail() {
	local code="$1"
	cleanup_build
	if [ "$STARTED" -eq 1 ] && [ -s "$LOG" ]; then
		printf '\nInstallation failed. Last lines of %s:\n' "$LOG" >&2
		tail -n 25 "$LOG" >&2 || true
	fi
	exit "$code"
}

usage() {
	cat <<'EOF'
Usage: install.sh [options]

  --domain <name>   domain already pointing at this server
  --email <addr>    email for certificate expiry notices
  --branch <name>   build this source branch instead of using a release
  --version <tag>   install this release (for example v0.3.0)
  --build           build from source even when a release exists
  --yes             do not ask for confirmation
  --force           continue on unsupported systems or busy ports
  --uninstall       remove Veyl (keeps /var/lib/veyl)
  --purge           with --uninstall, also delete /var/lib/veyl
  --panel           also install Veyl Control, the optional fleet panel
  --panel-only      install only Veyl Control on this server, no VPN node
  --panel-domain <name>  domain for Veyl Control (must differ from the node)
EOF
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--domain)
			[ "$#" -ge 2 ] || die "--domain needs a value"
			DOMAIN="$2"
			shift 2
			;;
		--email)
			[ "$#" -ge 2 ] || die "--email needs a value"
			EMAIL="$2"
			shift 2
			;;
		--branch)
			[ "$#" -ge 2 ] || die "--branch needs a value"
			BRANCH="$2"
			BRANCH_SET=1
			shift 2
			;;
		--version)
			[ "$#" -ge 2 ] || die "--version needs a value"
			VERSION="$2"
			shift 2
			;;
		--build)
			FORCE_BUILD=1
			shift
			;;
		--yes | -y)
			ASSUME_YES=1
			shift
			;;
		--force)
			FORCE=1
			shift
			;;
		--uninstall)
			UNINSTALL=1
			shift
			;;
		--purge)
			PURGE=1
			shift
			;;
		--panel)
			PANEL=1
			shift
			;;
		--panel-only)
			PANEL=1
			PANEL_ONLY=1
			shift
			;;
		--panel-domain)
			[ "$#" -ge 2 ] || die "--panel-domain needs a value"
			PANEL_DOMAIN="$2"
			PANEL=1
			shift 2
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			usage >&2
			die "unknown option: $1"
			;;
		esac
	done
	if [ -n "$DOMAIN" ] && ! [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
		die "invalid domain: $DOMAIN"
	fi
	if [ -n "$PANEL_DOMAIN" ] && ! [[ "$PANEL_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
		die "invalid panel domain: $PANEL_DOMAIN"
	fi
	if [ -n "$PANEL_DOMAIN" ] && [ "$PANEL_DOMAIN" = "$DOMAIN" ]; then
		die "the panel needs its own domain, different from the node domain"
	fi
	if [ -n "$EMAIL" ] && ! [[ "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]; then
		die "invalid email: $EMAIL"
	fi
	if ! [[ "$BRANCH" =~ ^[A-Za-z0-9._/-]{1,100}$ ]] || [[ "$BRANCH" == -* ]]; then
		die "invalid branch: $BRANCH"
	fi
	if [ -n "$VERSION" ] && ! valid_tag "$VERSION"; then
		die "invalid version: $VERSION"
	fi
}

run() {
	"$@" >>"$LOG" 2>&1
}

valid_tag() {
	[[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]{1,32})?$ ]]
}

resolve_release() {
	[ "$FORCE_BUILD" -eq 0 ] && [ "$BRANCH_SET" -eq 0 ] || return 1
	local tag="$VERSION"
	if [ -z "$tag" ]; then
		tag="$(curl -fsSL --proto '=https' --tlsv1.2 --max-time 20 -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$REPO_SLUG/releases/latest" 2>/dev/null |
			grep -o '"tag_name": *"[^"]*"' | head -n 1 | sed 's/^.*"\([^"]*\)"$/\1/')" || tag=""
	fi
	valid_tag "$tag" || return 1
	RELEASE="$tag"
	BRANCH="$tag"
}

download_release() {
	local ver="${RELEASE#v}" file sums base
	file="veyl_${ver}_linux_${ARCH}.tar.gz"
	base="$RELEASES/$RELEASE"
	step "Downloading veyl $RELEASE"
	rm -rf "$BUILD_DIR"
	mkdir -p "$BUILD_DIR"
	run curl -fsSL --proto '=https' --tlsv1.2 -o "$BUILD_DIR/SHA256SUMS" "$base/SHA256SUMS" || return 1
	run curl -fsSL --proto '=https' --tlsv1.2 -o "$BUILD_DIR/$file" "$base/$file" || return 1
	sums="$(grep -E "^[0-9a-f]{64}  \*?$file\$" "$BUILD_DIR/SHA256SUMS" || true)"
	[ "$(printf '%s\n' "$sums" | grep -c .)" -eq 1 ] || die "SHA256SUMS has no single entry for $file"
	(cd "$BUILD_DIR" && printf '%s\n' "$sums" | sha256sum -c --status -) || die "checksum mismatch for $file"
	run tar -C "$BUILD_DIR" -xzf "$BUILD_DIR/$file" veyl
	[ -f "$BUILD_DIR/veyl" ] || die "release archive has no veyl binary"
	install -m 0755 -o root -g root "$BUILD_DIR/veyl" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	cleanup_build
	say "    veyl $RELEASE (release, checksum verified)"
}

cleanup_build() {
	rm -rf "$BUILD_DIR"
	if [ "$TEMP_SWAP" -eq 1 ]; then
		swapoff "$SWAPFILE" >/dev/null 2>&1 || true
		rm -f "$SWAPFILE"
		TEMP_SWAP=0
	fi
}

confirm() {
	[ "$ASSUME_YES" -eq 1 ] && return 0
	if [ -r /dev/tty ] && [ -w /dev/tty ]; then
		local answer=""
		printf '%s [Y/n] ' "$1" >/dev/tty
		read -r answer </dev/tty || answer=""
		case "$answer" in
		"" | y | Y | yes | YES) return 0 ;;
		*) die "aborted" ;;
		esac
	fi
	return 0
}

check_root() {
	[ "$(id -u)" -eq 0 ] || die "run as root, for example: curl -fsSL https://raw.githubusercontent.com/VeylVPN/backend/main/install.sh | sudo bash"
}

os_field() {
	awk -F= -v k="$1" '$1 == k { v = $2; gsub(/^["\047]|["\047]$/, "", v); print v; exit }' /etc/os-release
}

check_os() {
	[ -r /etc/os-release ] || die "cannot read /etc/os-release"
	local id version
	id="$(os_field ID)"
	version="$(os_field VERSION_ID)"
	case "$id:$version" in
	debian:12 | debian:13 | ubuntu:22.04 | ubuntu:24.04) ;;
	*)
		if [ "$FORCE" -eq 1 ]; then
			say "Warning: $id $version is not supported, continuing because of --force"
		else
			die "unsupported system $id $version (supported: Debian 12/13, Ubuntu 22.04/24.04; use --force to try anyway)"
		fi
		;;
	esac
	command -v dpkg >/dev/null 2>&1 || die "dpkg not found"
	ARCH="$(dpkg --print-architecture)"
	case "$ARCH" in
	amd64 | arm64) ;;
	*) die "unsupported architecture $ARCH (amd64 and arm64 are supported)" ;;
	esac
	[ -d /run/systemd/system ] || die "systemd is not running as init"
	[ "$(cat /proc/1/comm 2>/dev/null)" = "systemd" ] || die "PID 1 is not systemd"
	[ "$PANEL_ONLY" -eq 1 ] && return 0
	if [ ! -c /dev/net/tun ]; then
		mkdir -p /dev/net
		mknod /dev/net/tun c 10 200 >/dev/null 2>&1 || true
		chmod 600 /dev/net/tun >/dev/null 2>&1 || true
	fi
	[ -c /dev/net/tun ] || die "/dev/net/tun is missing; enable TUN/TAP in your VPS control panel"
}

port_owner() {
	local proto="$1" port="$2" flag="-ltnpH"
	[ "$proto" = "udp" ] && flag="-lunpH"
	ss "$flag" 2>/dev/null | awk -v p=":$port" '{ for (i = 1; i <= NF; i++) if ($i ~ p "$") { print; next } }' |
		grep -o 'users:(("[^"]*"' | sed 's/users:(("//; s/"$//' | sort -u | tr '\n' ' ' || true
}

check_ports() {
	local conflicts="" spec proto port owners name
	for spec in tcp:80 tcp:443 udp:1194; do
		proto="${spec%%:*}"
		port="${spec##*:}"
		owners="$(port_owner "$proto" "$port")"
		for name in $owners; do
			case "$name" in
			caddy | openvpn | veyl) ;;
			*) conflicts="$conflicts $port/$proto ($name)" ;;
			esac
		done
	done
	if [ -n "$conflicts" ]; then
		if [ "$FORCE" -eq 1 ]; then
			say "Warning: ports in use:$conflicts"
		else
			die "ports in use:$conflicts. Stop those services or rerun with --force"
		fi
	fi
}

check_memory() {
	local kb
	kb="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
	if [ "${kb:-0}" -lt 1000000 ] && [ ! -e "$SWAPFILE" ]; then
		step "Low memory, adding a temporary swap file for the build"
		run fallocate -l 1G "$SWAPFILE" || run dd if=/dev/zero of="$SWAPFILE" bs=1M count=1024
		chmod 600 "$SWAPFILE"
		run mkswap "$SWAPFILE"
		run swapon "$SWAPFILE"
		TEMP_SWAP=1
	fi
}

apt_get() {
	DEBIAN_FRONTEND=noninteractive run apt-get -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -y "$@"
}

add_caddy_repo() {
	local key=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
	apt_get install debian-keyring debian-archive-keyring apt-transport-https gnupg curl ca-certificates
	curl -fsSL --proto '=https' --tlsv1.2 https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o "$key.tmp"
	mv "$key.tmp" "$key"
	chmod 644 "$key"
	curl -fsSL --proto '=https' --tlsv1.2 https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt -o /etc/apt/sources.list.d/caddy-stable.list.tmp
	grep -q '^deb .*dl.cloudsmith.io/public/caddy/stable' /etc/apt/sources.list.d/caddy-stable.list.tmp || die "unexpected Caddy repository file"
	mv /etc/apt/sources.list.d/caddy-stable.list.tmp /etc/apt/sources.list.d/caddy-stable.list
	chmod 644 /etc/apt/sources.list.d/caddy-stable.list
	apt_get update
}

install_packages() {
	step "Installing system packages"
	apt_get update
	local candidate
	candidate="$(apt-cache policy caddy 2>/dev/null | awk '/Candidate:/ { print $2 }')"
	if [ -z "$candidate" ] || [ "$candidate" = "(none)" ]; then
		add_caddy_repo
	fi
	if [ "$PANEL_ONLY" -eq 1 ]; then
		apt_get install caddy certbot ca-certificates curl git iproute2 tar
	elif [ "$PANEL" -eq 1 ]; then
		apt_get install openvpn nftables unbound caddy certbot ca-certificates curl git iproute2 openssl unattended-upgrades tar
	else
		apt_get install openvpn nftables unbound caddy ca-certificates curl git iproute2 openssl unattended-upgrades tar
	fi
}

fetch_source() {
	step "Fetching source ($BRANCH)"
	mkdir -p "$(dirname "$SRC_DIR")"
	if [ -d "$SRC_DIR/.git" ]; then
		run git -C "$SRC_DIR" remote set-url origin "$REPO_URL"
		run git -C "$SRC_DIR" fetch --depth 1 --tags origin "$BRANCH"
		run git -C "$SRC_DIR" reset --hard FETCH_HEAD
		run git -C "$SRC_DIR" clean -fdx
	else
		rm -rf "$SRC_DIR"
		run git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
	fi
	grep -q "^module $MODULE\$" "$SRC_DIR/go.mod" || die "unexpected source checkout"
}

script_sum() {
	local self="${BASH_SOURCE[0]:-}"
	if [ -n "$self" ] && [ -f "$self" ]; then
		sha256sum "$self" | awk '{ print $1 }'
	fi
}

maybe_reexec() {
	if [ "${VEYL_REEXEC:-0}" = "1" ] || [ -z "$SELF_SUM" ] || [ ! -f "$SRC_DIR/install.sh" ]; then
		return 0
	fi
	if [ "$(sha256sum "$SRC_DIR/install.sh" | awk '{ print $1 }')" = "$SELF_SUM" ]; then
		return 0
	fi
	step "Continuing with the installer from the fetched source"
	local args=(--yes)
	if [ -n "$RELEASE" ]; then
		args+=(--version "$RELEASE")
	else
		args+=(--branch "$BRANCH")
	fi
	[ "$FORCE_BUILD" -eq 1 ] && args+=(--build)
	[ -n "$DOMAIN" ] && args+=(--domain "$DOMAIN")
	[ -n "$EMAIL" ] && args+=(--email "$EMAIL")
	[ "$FORCE" -eq 1 ] && args+=(--force)
	[ "$PANEL" -eq 1 ] && args+=(--panel)
	[ "$PANEL_ONLY" -eq 1 ] && args+=(--panel-only)
	[ -n "$PANEL_DOMAIN" ] && args+=(--panel-domain "$PANEL_DOMAIN")
	export VEYL_REEXEC=1
	exec bash "$SRC_DIR/install.sh" "${args[@]}"
}

go_release() {
	local json
	json="$(curl -fsSL --proto '=https' --tlsv1.2 'https://go.dev/dl/?mode=json')" || die "cannot reach go.dev"
	printf '%s' "$json" | tr ',{}[]' '\n' | awk -v arch="$ARCH" '
		/"filename"/ {
			f = $0
			sub(/^[^:]*:[ \t]*"/, "", f)
			sub(/".*$/, "", f)
			want = (f ~ ("^go1\\.[0-9]+(\\.[0-9]+)?\\.linux-" arch "\\.tar\\.gz$"))
			next
		}
		/"sha256"/ && want {
			s = $0
			sub(/^[^:]*:[ \t]*"/, "", s)
			sub(/".*$/, "", s)
			print f, s
			exit
		}'
}

build() {
	step "Downloading the Go toolchain"
	local rel file sum ver
	rel="$(go_release)"
	file="${rel%% *}"
	sum="${rel##* }"
	[[ "$file" =~ ^go1\.[0-9]+(\.[0-9]+)?\.linux-(amd64|arm64)\.tar\.gz$ ]] || die "could not find a Go release for $ARCH"
	[[ "$sum" =~ ^[0-9a-f]{64}$ ]] || die "could not find the Go checksum"
	rm -rf "$BUILD_DIR"
	mkdir -p "$BUILD_DIR"
	run curl -fsSL --proto '=https' --tlsv1.2 -o "$BUILD_DIR/$file" "https://go.dev/dl/$file"
	printf '%s  %s\n' "$sum" "$BUILD_DIR/$file" | sha256sum -c --status - || die "Go toolchain checksum mismatch"
	run tar -C "$BUILD_DIR" -xzf "$BUILD_DIR/$file"
	rm -f "$BUILD_DIR/$file"

	step "Building veyl"
	ver="$(git -C "$SRC_DIR" describe --tags --always --dirty 2>/dev/null || printf 'unknown')"
	[[ "$ver" =~ ^[A-Za-z0-9._+-]{1,64}$ ]] || ver="unknown"
	(
		cd "$SRC_DIR"
		export GOROOT="$BUILD_DIR/go"
		export GOPATH="$BUILD_DIR/gopath"
		export GOCACHE="$BUILD_DIR/cache"
		export GOMODCACHE="$BUILD_DIR/modcache"
		export GOTOOLCHAIN=local
		export GOPROXY=off
		export CGO_ENABLED=0
		run "$BUILD_DIR/go/bin/go" build -trimpath -ldflags "-s -w -X $MODULE/internal/app.Version=$ver" -o "$BUILD_DIR/veyl" ./cmd/veyl
	)
	install -m 0755 -o root -g root "$BUILD_DIR/veyl" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	cleanup_build
	say "    veyl $ver"
}

create_users() {
	getent group veyl >/dev/null || run groupadd --system veyl
	getent passwd veyl >/dev/null || run useradd --system --gid veyl --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin veyl
	getent passwd veyl-ovpn >/dev/null || run useradd --system --gid veyl --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin veyl-ovpn
	install -d -m 0750 -o veyl -g veyl "$DATA_DIR"
}

init_pki() {
	step "Preparing keys"
	if [ -f "$DATA_DIR/ca.key" ] && [ -f "$DATA_DIR/server.key" ]; then
		say "    existing keys kept"
	fi
	run "$BIN" init "$DATA_DIR"
}

configure() {
	step "Configuring the system"
	local args=()
	[ -n "$DOMAIN" ] && args+=(-domain "$DOMAIN")
	[ -n "$EMAIL" ] && args+=(-email "$EMAIL")
	if ! "$BIN" agent bootstrap "${args[@]}" | tee -a "$LOG" | sed 's/^/    /'; then
		die "system configuration failed"
	fi
}

configured() {
	[ -f "$DATA_DIR/settings.json" ] && grep -q '"configured": *true' "$DATA_DIR/settings.json"
}

public_ip() {
	local a b
	a="$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
	b="$(curl -4 -fsS --max-time 8 https://ifconfig.co/ip 2>/dev/null || true)"
	if [[ "$a" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
		printf '%s' "$a"
	elif [[ "$b" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
		printf '%s' "$b"
	else
		ip -4 -o addr show scope global 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4; exit }'
	fi
}

setup_token() {
	local token tmp
	token="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
	tmp="$(mktemp "$DATA_DIR/.setup-token.XXXXXX")"
	printf '%s' "$token" >"$tmp"
	chown veyl:veyl "$tmp"
	chmod 600 "$tmp"
	mv -f "$tmp" "$DATA_DIR/setup-token"
	printf '%s' "$token"
}

https_ready() {
	[ -n "$DOMAIN" ] || return 1
	curl -fsS --max-time 10 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/v1/health" >/dev/null 2>&1
}

banner() {
	local url="$1"
	local line="=================================================================="
	printf '\n\033[1;32m%s\033[0m\n\n' "$line"
	printf '  \033[1mVeyl is installed.\033[0m\n\n'
	printf '  Open this link to finish setup:\n\n'
	printf '    \033[1m%s\033[0m\n\n' "$url"
	printf '  If you have no domain, setup can give you one automatically.\n'
	printf '  The link works once. Lost it? Run: sudo veyl setup-link\n'
	printf '\n\033[1;32m%s\033[0m\n\n' "$line"
}

finish() {
	if configured; then
		printf '\n\033[1;32mVeyl is up to date and running.\033[0m Check it with: sudo veyl status\n\n'
		return 0
	fi
	local token host url
	token="$(setup_token)"
	if https_ready; then
		url="https://$DOMAIN/setup#$token"
	else
		host="$(public_ip)"
		[ -n "$host" ] || host="<server-ip>"
		url="http://$host/setup#$token"
	fi
	banner "$url"
}

panel_install() {
	step "Installing Veyl Control"
	local args=()
	[ -n "$PANEL_DOMAIN" ] && args+=(-domain "$PANEL_DOMAIN")
	[ -n "$EMAIL" ] && args+=(-email "$EMAIL")
	local ip
	ip="$(public_ip)"
	[ -n "$ip" ] && args+=(-ip "$ip")
	if ! "$BIN" panel install "${args[@]}" | tee -a "$LOG"; then
		die "Veyl Control installation failed"
	fi
}

detect_panel() {
	if [ -d "$PANEL_DIR" ] && [ -f /etc/systemd/system/veyl-panel.service ]; then
		PANEL=1
		if [ ! -f "$DATA_DIR/ca.key" ]; then
			PANEL_ONLY=1
		fi
	fi
}

do_uninstall() {
	step "Removing Veyl"
	if [ -x "$BIN" ] && [ -f /etc/systemd/system/veyl-panel.service ]; then
		local pargs=()
		[ "$PURGE" -eq 1 ] && pargs+=(-purge)
		"$BIN" panel uninstall "${pargs[@]}" || true
		[ "$PURGE" -eq 1 ] && rm -rf "$PANEL_DIR"
	fi
	if [ -x "$BIN" ]; then
		local args=()
		[ "$PURGE" -eq 1 ] && args+=(-purge)
		"$BIN" agent uninstall "${args[@]}" || true
	fi
	rm -f "$BIN"
	rm -rf /opt/veyl
	if [ "$PURGE" -eq 1 ]; then
		rm -rf "$DATA_DIR"
		say "Veyl and its data were removed."
	else
		say "Veyl was removed. Keys and accounts are kept in $DATA_DIR (use --uninstall --purge to delete them)."
	fi
}

main() {
	parse_args "$@"
	check_root
	SELF_SUM="$(script_sum)"
	umask 022
	if [ "$UNINSTALL" -eq 1 ]; then
		confirm "Remove Veyl from this server?"
		do_uninstall
		return 0
	fi
	: >"$LOG"
	chmod 600 "$LOG"
	STARTED=1
	trap 'fail "$?"' ERR
	trap 'cleanup_build' EXIT
	detect_panel
	check_os
	if [ -x "$BIN" ] && { [ -f "$DATA_DIR/ca.key" ] || [ "$PANEL_ONLY" -eq 1 ]; }; then
		step "Existing installation found, updating and repairing"
	else
		check_ports
		confirm "Install Veyl on this server?"
	fi
	install_packages
	resolve_release || true
	fetch_source
	maybe_reexec
	if [ -z "$RELEASE" ] || ! download_release; then
		[ -n "$RELEASE" ] && say "    release download failed, building $RELEASE from source"
		check_memory
		build
	fi
	if [ "$PANEL_ONLY" -eq 0 ]; then
		create_users
		init_pki
		configure
		finish
	fi
	if [ "$PANEL" -eq 1 ]; then
		panel_install
	fi
	trap - ERR
	rm -f "$LOG"
}

main "$@"; exit "$?"
