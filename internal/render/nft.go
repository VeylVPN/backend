package render

import (
	"fmt"

	"github.com/veylvpn/backend/internal/config"
)

const (
	privateV4 = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4"
	privateV6 = "::1/128, fc00::/7, fe80::/10, ff00::/8"
)

func NFTables(s config.Settings, f Facts) (string, error) {
	if err := checkSettings(s); err != nil {
		return "", err
	}
	ports, err := sshPorts(f)
	if err != nil {
		return "", err
	}
	if err := checkWAN(f); err != nil {
		return "", err
	}
	tuns := fmt.Sprintf("{ \"%s\", \"%s\" }", config.TunUDP, config.TunTCP)
	wan := fmt.Sprintf("\"%s\"", f.WANIface)
	v6 := IPv6(s, f)
	var l lines
	l.add("table inet veyl")
	l.add("delete table inet veyl")
	l.add("table inet veyl {")
	l.indent = "\t"
	l.add("chain input {")
	l.indent = "\t\t"
	l.add("type filter hook input priority filter; policy drop;")
	l.add("ct state established,related accept")
	l.add("ct state invalid drop")
	l.add("iif \"lo\" accept")
	l.add("meta l4proto icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept")
	l.add("meta l4proto icmp icmp type echo-request limit rate 5/second burst 10 packets accept")
	l.add("meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept")
	l.add("meta l4proto ipv6-icmp icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept")
	l.add("meta l4proto ipv6-icmp icmpv6 type echo-request limit rate 5/second burst 10 packets accept")
	l.add("ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept")
	l.add("tcp dport { %s } accept", joinInts(ports))
	l.add("tcp dport { 80, 443 } accept")
	if s.Configured {
		l.add("udp dport %d accept", s.UDPPort)
	}
	dnsIn := fmt.Sprintf("{ \"%s\", \"%s\", \"lo\" }", config.TunUDP, config.TunTCP)
	l.add("iifname %s ip daddr %s.0/24 udp dport 53 accept", dnsIn, config.DNSPrefix)
	l.add("iifname %s ip daddr %s.0/24 tcp dport 53 accept", dnsIn, config.DNSPrefix)
	if s.AdminVPNOnly {
		l.add("iifname %s ip daddr { %s, %s } tcp dport %d accept", tuns, config.UDPGW4, config.TCPGW4, AdminVPNPort)
	}
	l.indent = "\t"
	l.add("}")
	l.blank()
	l.add("chain forward {")
	l.indent = "\t\t"
	l.add("type filter hook forward priority filter; policy drop;")
	l.add("tcp flags syn tcp option maxseg size set rt mtu")
	l.add("ct state established,related accept")
	l.add("ct state invalid drop")
	l.add("iifname %s ip daddr { %s } drop", tuns, privateV4)
	l.add("iifname %s ip6 daddr { %s } drop", tuns, privateV6)
	l.add("iifname %s oifname %s meta nfproto ipv4 accept", tuns, wan)
	if v6 {
		l.add("iifname %s oifname %s meta nfproto ipv6 accept", tuns, wan)
	}
	l.indent = "\t"
	l.add("}")
	l.indent = ""
	l.add("}")
	l.blank()
	l.add("table ip veyl_nat")
	l.add("delete table ip veyl_nat")
	l.add("table ip veyl_nat {")
	l.indent = "\t"
	l.add("chain postrouting {")
	l.indent = "\t\t"
	l.add("type nat hook postrouting priority srcnat; policy accept;")
	l.add("oifname %s ip saddr { %s/24, %s/24 } masquerade", wan, config.UDPNet4, config.TCPNet4)
	l.indent = "\t"
	l.add("}")
	l.indent = ""
	l.add("}")
	l.blank()
	l.add("table ip6 veyl_nat6")
	l.add("delete table ip6 veyl_nat6")
	if v6 {
		l.add("table ip6 veyl_nat6 {")
		l.indent = "\t"
		l.add("chain postrouting {")
		l.indent = "\t\t"
		l.add("type nat hook postrouting priority srcnat; policy accept;")
		l.add("oifname %s ip6 saddr { %s, %s } masquerade", wan, config.UDPNet6, config.TCPNet6)
		l.indent = "\t"
		l.add("}")
		l.indent = ""
		l.add("}")
	}
	return l.String(), nil
}

func NFTDelete() string {
	var l lines
	for _, t := range []string{"inet veyl", "ip veyl_nat", "ip6 veyl_nat6"} {
		l.add("table %s", t)
		l.add("delete table %s", t)
	}
	return l.String()
}
