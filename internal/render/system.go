package render

import (
	"fmt"
	"strings"

	"github.com/veylvpn/backend/internal/config"
)

func Sysctl(f Facts) (string, error) {
	if err := checkWAN(f); err != nil {
		return "", err
	}
	var l lines
	l.add("net.ipv4.ip_forward = 1")
	l.add("net.ipv6.conf.all.forwarding = 1")
	l.add("net/ipv6/conf/%s/accept_ra = 2", f.WANIface)
	l.add("net.netfilter.nf_conntrack_acct = 0")
	l.add("net.netfilter.nf_conntrack_timestamp = 0")
	l.add("net.netfilter.nf_conntrack_helper = 0")
	l.add("net.ipv4.conf.all.rp_filter = 1")
	l.add("net.ipv4.conf.default.rp_filter = 1")
	l.add("net.ipv4.conf.all.accept_redirects = 0")
	l.add("net.ipv4.conf.default.accept_redirects = 0")
	l.add("net.ipv6.conf.all.accept_redirects = 0")
	l.add("net.ipv6.conf.default.accept_redirects = 0")
	l.add("net.ipv4.conf.all.send_redirects = 0")
	l.add("net.ipv4.conf.default.send_redirects = 0")
	l.add("net.ipv4.conf.all.accept_source_route = 0")
	l.add("net.ipv6.conf.all.accept_source_route = 0")
	l.add("net.ipv4.tcp_syncookies = 1")
	l.add("kernel.dmesg_restrict = 1")
	l.add("kernel.kptr_restrict = 2")
	l.add("fs.suid_dumpable = 0")
	l.add("kernel.core_pattern = |/bin/false")
	return l.String(), nil
}

func Journald() string {
	var l lines
	l.add("[Journal]")
	l.add("Storage=none")
	l.add("ForwardToSyslog=no")
	l.add("ForwardToKMsg=no")
	l.add("ForwardToConsole=no")
	l.add("ForwardToWall=no")
	return l.String()
}

func SSHD() string {
	return "LogLevel QUIET\n"
}

func Unattended(s config.Settings) (string, error) {
	if err := checkSettings(s); err != nil {
		return "", err
	}
	on := "0"
	if s.AutoUpdates {
		on = "1"
	}
	var l lines
	l.add("APT::Periodic::Update-Package-Lists \"%s\";", on)
	l.add("APT::Periodic::Unattended-Upgrade \"%s\";", on)
	l.add("APT::Periodic::AutocleanInterval \"7\";")
	l.add("Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";")
	l.add("Unattended-Upgrade::Automatic-Reboot \"false\";")
	l.add("Unattended-Upgrade::SyslogEnable \"false\";")
	return l.String(), nil
}

func Tmpfiles() string {
	return fmt.Sprintf("d %s 2770 root %s -\n", config.RunDir, config.ServiceUser)
}

const DNSLink = "lo"

func DNSInterface() string {
	var l lines
	for i := 1; i <= config.MaxMask()+1; i++ {
		l.add("address replace %s.%d/32 dev %s", config.DNSPrefix, i, DNSLink)
	}
	return l.String()
}

func DNSInterfaceDown() string {
	var l lines
	for i := 1; i <= config.MaxMask()+1; i++ {
		l.add("address delete %s.%d/32 dev %s", config.DNSPrefix, i, DNSLink)
	}
	return l.String()
}

type Privacy struct {
	NullLinks []string
	Remove    []string
	Disable   []string
	Mask      []string
}

func PrivacyPlan() Privacy {
	return Privacy{
		NullLinks: []string{"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"},
		Remove:    []string{"/var/log/cloud-init.log", "/var/log/cloud-init-output.log", "/var/log/journal"},
		Disable:   []string{"rsyslog.service", "syslog.socket"},
		Mask:      []string{"systemd-coredump.socket"},
	}
}

func StripSwap(fstab string) (string, bool) {
	var b strings.Builder
	changed := false
	for _, line := range strings.SplitAfter(fstab, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && !strings.HasPrefix(fields[0], "#") && fields[2] == "swap" {
			changed = true
			continue
		}
		b.WriteString(line)
	}
	return b.String(), changed
}
