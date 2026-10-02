package agent

import (
	"context"
	"errors"
	"strings"

	"github.com/veylvpn/backend/internal/render"
)

var restartUnits = map[string]string{
	"veyl":                    render.UnitVeyl,
	"veyl-dns":                render.UnitDNS,
	"veyl-dnsif":              render.UnitDNSIf,
	"veyl-firewall":           render.UnitFirewall,
	"openvpn-server@veyl-udp": render.UnitOpenVPNUDP,
	"openvpn-server@veyl-tcp": render.UnitOpenVPNTCP,
	"unbound":                 render.UnitUnbound,
	"caddy":                   render.UnitCaddy,
}

var ErrService = errors.New("unknown service")

func (a *Agent) RestartService(ctx context.Context, emit Emit, name string) error {
	a.init()
	u, ok := restartUnits[name]
	if !ok {
		return ErrService
	}
	if u == render.UnitOpenVPNTCP {
		s, err := a.settings()
		if err != nil {
			return err
		}
		if !s.Stealth {
			return step(emit, name, func() (string, error) { return "", skip("stealth is off") })
		}
	}
	return step(emit, name, func() (string, error) {
		if u == render.UnitVeyl {
			return "restart queued", a.systemctl(ctx, "restart", "--no-block", u)
		}
		if err := a.systemctl(ctx, "restart", u); err != nil {
			return "", err
		}
		if !a.active(ctx, u) {
			return "", errors.New(strings.TrimSuffix(u, ".service") + " did not come back")
		}
		return "restarted", nil
	})
}

const UpdateUnit = "veyl-update"

func (a *Agent) Update(ctx context.Context, emit Emit) error {
	a.init()
	return a.runUpdate(ctx, emit, UpdateUnit)
}

func (a *Agent) runUpdate(ctx context.Context, emit Emit, unit string) error {
	argv, err := UpdateArgs("")
	if err != nil {
		return err
	}
	if err := step(emit, "installer", func() (string, error) {
		if !a.exists(InstallPath) {
			return "", errors.New("installer not found at " + InstallPath)
		}
		return InstallPath, nil
	}); err != nil {
		return err
	}
	return step(emit, "update", func() (string, error) {
		args := append([]string{"--unit", unit, "--collect", "--quiet", "--property=Type=exec", "--setenv=LC_ALL=C.UTF-8"}, argv...)
		if _, err := a.run(ctx, quick, "systemd-run", args...); err != nil {
			if a.active(ctx, unit+".service") {
				return "", errors.New("an update is already running")
			}
			return "", err
		}
		return "update started in the background, services restart when it finishes", nil
	})
}
