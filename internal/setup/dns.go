package setup

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	typeA    = 1
	typeAAAA = 28
)

var (
	errDNSFormat = errors.New("malformed dns message")
	errNXDomain  = errors.New("no such domain")
)

func buildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, errDNSFormat
	}
	b := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(name, ".") {
		if len(l) == 0 || len(l) > 63 {
			return nil, errDNSFormat
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b, nil
}

func skipName(m []byte, off int) (int, error) {
	for hops := 0; hops < 128; hops++ {
		if off >= len(m) {
			return 0, errDNSFormat
		}
		l := int(m[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(m) {
				return 0, errDNSFormat
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, errDNSFormat
		default:
			off += 1 + l
		}
	}
	return 0, errDNSFormat
}

func parseAnswer(m []byte, id uint16, qtype uint16) ([]net.IP, error) {
	if len(m) < 12 {
		return nil, errDNSFormat
	}
	if binary.BigEndian.Uint16(m[0:]) != id {
		return nil, errDNSFormat
	}
	flags := binary.BigEndian.Uint16(m[2:])
	if flags&0x8000 == 0 {
		return nil, errDNSFormat
	}
	switch flags & 0x000f {
	case 0:
	case 3:
		return nil, errNXDomain
	default:
		return nil, errors.New("dns server error")
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	an := int(binary.BigEndian.Uint16(m[6:]))
	if qd > 4 || an > 256 {
		return nil, errDNSFormat
	}
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(m, off); err != nil {
			return nil, err
		}
		off += 4
		if off > len(m) {
			return nil, errDNSFormat
		}
	}
	var out []net.IP
	for i := 0; i < an; i++ {
		if off, err = skipName(m, off); err != nil {
			return nil, err
		}
		if off+10 > len(m) {
			return nil, errDNSFormat
		}
		t := binary.BigEndian.Uint16(m[off:])
		c := binary.BigEndian.Uint16(m[off+2:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			return nil, errDNSFormat
		}
		rd := m[off : off+rdlen]
		off += rdlen
		if c != 1 || t != qtype {
			continue
		}
		if t == typeA && rdlen == 4 {
			out = append(out, net.IP(append([]byte(nil), rd...)))
		}
		if t == typeAAAA && rdlen == 16 {
			out = append(out, net.IP(append([]byte(nil), rd...)))
		}
	}
	return out, nil
}

func lookup(ctx context.Context, server, name string, qtype uint16, timeout time.Duration) ([]net.IP, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q, err := buildQuery(id, name, qtype)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		ips, perr := parseAnswer(buf[:n], id, qtype)
		if errors.Is(perr, errDNSFormat) {
			continue
		}
		return ips, perr
	}
}

type Resolution struct {
	A        []string
	AAAA     []string
	NX       bool
	Answered bool
}

func resolve(ctx context.Context, servers []string, name string, timeout time.Duration) Resolution {
	var mu sync.Mutex
	var wg sync.WaitGroup
	seenA := map[string]bool{}
	seen6 := map[string]bool{}
	res := Resolution{}
	for _, s := range servers {
		for _, qt := range []uint16{typeA, typeAAAA} {
			wg.Add(1)
			go func(s string, qt uint16) {
				defer wg.Done()
				ips, err := lookup(ctx, s, name, qt, timeout)
				mu.Lock()
				defer mu.Unlock()
				if errors.Is(err, errNXDomain) {
					res.NX = true
					res.Answered = true
					return
				}
				if err != nil {
					return
				}
				res.Answered = true
				for _, ip := range ips {
					k := ip.String()
					if qt == typeA && !seenA[k] {
						seenA[k] = true
						res.A = append(res.A, k)
					}
					if qt == typeAAAA && !seen6[k] {
						seen6[k] = true
						res.AAAA = append(res.AAAA, k)
					}
				}
			}(s, qt)
		}
	}
	wg.Wait()
	sort.Strings(res.A)
	sort.Strings(res.AAAA)
	return res
}

var cloudflareNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	} {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func isCloudflare(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type DNSCheck struct {
	Host    string   `json:"host"`
	IP      string   `json:"ip"`
	A       []string `json:"a"`
	AAAA    []string `json:"aaaa"`
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Note    string   `json:"note,omitempty"`
}

func evaluate(host, ip, ip6 string, r Resolution) DNSCheck {
	c := DNSCheck{Host: host, IP: ip, A: r.A, AAAA: r.AAAA}
	if c.A == nil {
		c.A = []string{}
	}
	if c.AAAA == nil {
		c.AAAA = []string{}
	}
	for _, x := range append(append([]string{}, r.A...), r.AAAA...) {
		if isCloudflare(x) {
			c.Status = "proxied"
			c.Message = "This name goes through Cloudflare's proxy. In Cloudflare, set this record to \"DNS only\" (grey cloud) so the VPN can reach your server."
			return c
		}
	}
	switch {
	case !r.Answered:
		c.Status = "error"
		c.Message = "We couldn't reach the DNS checkers. Check again in a moment."
		return c
	case len(r.A) == 0 && len(r.AAAA) == 0:
		c.Status = "missing"
		c.Message = "We can't find this name yet. Add an A record pointing to " + orUnknown(ip) + ". New records can take a few minutes."
		return c
	}
	match := false
	other := false
	for _, x := range r.A {
		if x == ip {
			match = true
		} else {
			other = true
		}
	}
	switch {
	case match && !other:
		c.Status = "ok"
		c.Message = "Looks good. This name points to your server."
	case match && other:
		c.Status = "mixed"
		c.Message = "This name points to your server and to other addresses. Remove the extra A records."
	case len(r.A) == 0:
		c.Status = "missing"
		c.Message = "This name has no A record. Add one pointing to " + orUnknown(ip) + "."
	default:
		c.Status = "wrong"
		c.Message = "This name points to " + strings.Join(r.A, ", ") + ", but your server is " + orUnknown(ip) + ". Update the A record."
	}
	if c.Status == "ok" && len(r.AAAA) > 0 {
		ok6 := ip6 != ""
		for _, x := range r.AAAA {
			if x != ip6 {
				ok6 = false
			}
		}
		if !ok6 {
			c.Note = "There is also an AAAA (IPv6) record that doesn't point here. Remove it or point it to this server."
		}
	}
	return c
}

func orUnknown(ip string) string {
	if ip == "" {
		return "this server's IP"
	}
	return ip
}
