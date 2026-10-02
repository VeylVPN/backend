package render

import (
	"path"
	"strings"

	"github.com/veylvpn/backend/internal/config"
)

func unit(sections ...[]string) string {
	var b strings.Builder
	for i, s := range sections {
		if i > 0 {
			b.WriteByte('\n')
		}
		for _, line := range s {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

var sandbox = []string{
	"NoNewPrivileges=yes",
	"ProtectSystem=strict",
	"ProtectHome=yes",
	"PrivateTmp=yes",
	"PrivateDevices=yes",
	"ProtectKernelTunables=yes",
	"ProtectKernelModules=yes",
	"ProtectKernelLogs=yes",
	"ProtectControlGroups=yes",
	"ProtectClock=yes",
	"ProtectHostname=yes",
	"RestrictNamespaces=yes",
	"RestrictRealtime=yes",
	"RestrictSUIDSGID=yes",
	"LockPersonality=yes",
	"MemoryDenyWriteExecute=yes",
	"SystemCallArchitectures=native",
	"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
}

func withSandbox(lines ...string) []string {
	return append(append([]string{}, lines...), sandbox...)
}

func Units() []File {
	bin := config.BinPath
	data := config.DataDir
	run := config.RunDir
	files := []File{
		{Path: UnitVeyl, Data: unit(
			[]string{"[Unit]", "Description=Veyl server", "After=network-online.target " + UnitAgent, "Wants=network-online.target " + UnitAgent},
			withSandbox("[Service]", "Type=simple", "User="+config.ServiceUser, "Group="+config.ServiceUser,
				"ExecStart="+bin+" serve", "Restart=always", "RestartSec=2", "UMask=0007",
				"CapabilityBoundingSet=", "ReadWritePaths="+data+" "+run),
			[]string{"[Install]", "WantedBy=multi-user.target"},
		)},
		{Path: UnitAgent, Data: unit(
			[]string{"[Unit]", "Description=Veyl root agent", "After=network-online.target", "Wants=network-online.target"},
			[]string{"[Service]", "Type=simple", "ExecStart=" + bin + " agent", "Restart=always", "RestartSec=2", "UMask=0022", "PrivateTmp=yes", "ProtectHome=yes"},
			[]string{"[Install]", "WantedBy=multi-user.target"},
		)},
		{Path: UnitDNS, Data: unit(
			[]string{"[Unit]", "Description=Veyl DNS filter", "After=network.target " + UnitDNSIf + " " + UnitUnbound, "Requires=" + UnitDNSIf, "Wants=" + UnitUnbound},
			withSandbox("[Service]", "Type=simple", "User="+config.ServiceUser, "Group="+config.ServiceUser,
				"ExecStart="+bin+" dns -blocklists "+path.Join(data, "blocklists")+" -upstream "+config.UnboundAddr,
				"ExecReload=/bin/kill -HUP $MAINPID", "Restart=always", "RestartSec=2",
				"AmbientCapabilities=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"),
			[]string{"[Install]", "WantedBy=multi-user.target"},
		)},
		{Path: UnitDNSIf, Data: unit(
			[]string{"[Unit]", "Description=Veyl DNS addresses", "After=network-pre.target", "Before=network.target " + UnitDNS},
			[]string{"[Service]", "Type=oneshot", "RemainAfterExit=yes",
				"ExecStart=/usr/sbin/ip -batch " + DNSIfFile,
				"ExecStop=-/usr/sbin/ip -force -batch " + DNSIfDownFile},
			[]string{"[Install]", "WantedBy=multi-user.target"},
		)},
		{Path: UnitFirewall, Data: unit(
			[]string{"[Unit]", "Description=Veyl firewall tables", "DefaultDependencies=no", "Wants=network-pre.target",
				"Before=network-pre.target shutdown.target", "After=local-fs.target nftables.service", "Conflicts=shutdown.target"},
			[]string{"[Service]", "Type=oneshot", "RemainAfterExit=yes",
				"ExecStart=/usr/sbin/nft -f " + NFTFile, "ExecReload=/usr/sbin/nft -f " + NFTFile},
			[]string{"[Install]", "WantedBy=sysinit.target"},
		)},
		{Path: UnitBlocklists, Data: unit(
			[]string{"[Unit]", "Description=Veyl blocklist update", "After=network-online.target " + UnitAgent, "Wants=network-online.target"},
			withSandbox("[Service]", "Type=oneshot", "User="+config.ServiceUser, "Group="+config.ServiceUser,
				"ExecStart="+bin+" agent run dns-update", "CapabilityBoundingSet="),
		)},
		{Path: UnitBlocklistsTmr, Data: unit(
			[]string{"[Unit]", "Description=Daily Veyl blocklist update"},
			[]string{"[Timer]", "OnCalendar=daily", "RandomizedDelaySec=4h", "AccuracySec=1h"},
			[]string{"[Install]", "WantedBy=timers.target"},
		)},
	}
	for _, name := range []string{UnitOpenVPNUDP, UnitOpenVPNTCP} {
		files = append(files, File{Path: name + ".d/veyl.conf", Data: unit(
			[]string{"[Unit]", "After=" + UnitDNSIf + " " + UnitFirewall, "Wants=" + UnitDNSIf},
			[]string{"[Service]", "ExecStart=", "ExecStart=/usr/sbin/openvpn --suppress-timestamps --config %i.conf",
				"UMask=0007", "LimitNPROC=64"},
		)})
	}
	for i := range files {
		files[i].Path = path.Join(UnitDir, files[i].Path)
		files[i].Mode = 0o644
	}
	return files
}

func UnitNames() []string {
	return []string{UnitVeyl, UnitAgent, UnitDNS, UnitDNSIf, UnitFirewall, UnitBlocklists, UnitBlocklistsTmr}
}
