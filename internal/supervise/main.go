package supervise

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/veylvpn/backend/internal/agent"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/winsvc"
)

func mgmt(inst string) *ovpn.Client {
	p := config.WindowsPaths()
	return &ovpn.Client{Socket: fmt.Sprintf("%s%s:%d", ovpn.TCPPrefix, config.MgmtHost, config.MgmtPort(inst)), PasswordFile: p.MgmtPassword(inst), Timeout: 3 * time.Second}
}

func WaitConnected(ctx context.Context, m interface{ State() (string, error) }, sleep func(context.Context, time.Duration) error, tries int) error {
	for i := 0; i < tries; i++ {
		if st, err := m.State(); err == nil && st == "CONNECTED" {
			return nil
		}
		if err := sleep(ctx, time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("openvpn did not come up")
}

func openvpnHooks(c *Child, inst string) {
	m := mgmt(inst)
	c.Stop = func() error { return m.Signal("SIGTERM") }
	c.Ready = func(ctx context.Context) error {
		o := Options{}
		o.defaults()
		if err := WaitConnected(ctx, m, o.Sleep, 120); err != nil {
			return err
		}
		a := agent.New()
		var err error
		for i := 0; i < 5; i++ {
			if err = a.TapUp(ctx, inst); err == nil {
				return nil
			}
			if serr := o.Sleep(ctx, 5*time.Second); serr != nil {
				return serr
			}
		}
		return err
	}
}

func Main(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: veyl supervise <openvpn-udp|openvpn-tcp|unbound|caddy>")
		return 2
	}
	if config.Platform != config.PlatformWindows {
		fmt.Fprintln(stderr, "veyl supervise is only used on Windows, systemd runs these services on Linux")
		return 2
	}
	c, err := Spec(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	switch args[0] {
	case UnitOpenVPNUDP:
		openvpnHooks(&c, config.InstanceUDP)
	case UnitOpenVPNTCP:
		openvpnHooks(&c, config.InstanceTCP)
	}
	if _, err := os.Stat(c.Path); err != nil {
		fmt.Fprintln(stderr, "missing", c.Path)
		return 1
	}
	if err := Run(winsvc.Context(), c, Options{}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
