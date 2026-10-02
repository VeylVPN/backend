package wg

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Manager struct {
	Iface   string
	Prefix  string
	Prefix6 string
}

func (m Manager) run(args ...string) ([]byte, error) {
	return exec.Command("wg", args...).Output()
}

func (m Manager) Addr4(idx int) string {
	return fmt.Sprintf("%s.%d/32", m.Prefix, idx)
}

func (m Manager) Addr6(idx int) string {
	return fmt.Sprintf("%s%x/128", m.Prefix6, idx)
}

func (m Manager) allowed(idx int) string {
	return m.Addr4(idx) + "," + m.Addr6(idx)
}

func (m Manager) AddPeer(pub string, idx int) error {
	_, err := m.run("set", m.Iface, "peer", pub, "allowed-ips", m.allowed(idx))
	return err
}

func (m Manager) RemovePeer(pub string) error {
	_, err := m.run("set", m.Iface, "peer", pub, "remove")
	return err
}

func (m Manager) ServerPublicKey() (string, error) {
	b, err := m.run("show", m.Iface, "public-key")
	return strings.TrimSpace(string(b)), err
}

func (m Manager) ScrubIdle(idx map[string]int, idle time.Duration) {
	b, err := m.run("show", m.Iface, "latest-handshakes")
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || now-ts < int64(idle.Seconds()) {
			continue
		}
		i, ok := idx[f[0]]
		if !ok {
			continue
		}
		_ = m.RemovePeer(f[0])
		_ = m.AddPeer(f[0], i)
	}
}
