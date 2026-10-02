package supervise

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/render"
)

const (
	UnitOpenVPNUDP = "openvpn-udp"
	UnitOpenVPNTCP = "openvpn-tcp"
	UnitUnbound    = "unbound"
	UnitCaddy      = "caddy"
)

var ErrUnit = errors.New("unknown supervised unit")

type Child struct {
	Unit  string
	Path  string
	Args  []string
	Dir   string
	Env   []string
	Ready func(ctx context.Context) error
	Stop  func() error
}

type Options struct {
	MinBackoff time.Duration
	MaxBackoff time.Duration
	Healthy    time.Duration
	StopGrace  time.Duration
	Sleep      func(ctx context.Context, d time.Duration) error
	Started    func(n int)
}

func (o *Options) defaults() {
	if o.MinBackoff == 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = time.Minute
	}
	if o.Healthy == 0 {
		o.Healthy = 2 * time.Minute
	}
	if o.StopGrace == 0 {
		o.StopGrace = 5 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
}

func Spec(unit string) (Child, error) {
	switch unit {
	case UnitOpenVPNUDP, UnitOpenVPNTCP:
		inst := config.InstanceUDP
		if unit == UnitOpenVPNTCP {
			inst = config.InstanceTCP
		}
		return Child{Unit: unit, Path: config.WinOpenVPNBin, Args: []string{"--config", render.WinOpenVPNPath(inst)}, Dir: config.WinConfDir}, nil
	case UnitUnbound:
		return Child{Unit: unit, Path: config.Join(config.WinUnboundDir, "unbound.exe"), Args: []string{"-d", "-c", render.WinUnboundPath()}, Dir: config.WinUnboundData}, nil
	case UnitCaddy:
		return Child{Unit: unit, Path: config.WinCaddyBin, Args: []string{"run", "--config", render.WinCaddyfilePath(), "--adapter", "caddyfile"}, Dir: config.WinCaddyData, Env: []string{
			"XDG_DATA_HOME=" + config.Join(config.WinCaddyData, "data"),
			"XDG_CONFIG_HOME=" + config.Join(config.WinCaddyData, "config"),
		}}, nil
	}
	return Child{}, ErrUnit
}

func Run(ctx context.Context, c Child, o Options) error {
	o.defaults()
	if c.Path == "" {
		return ErrUnit
	}
	backoff := o.MinBackoff
	for n := 1; ; n++ {
		started := time.Now()
		if o.Started != nil {
			o.Started(n)
		}
		_ = once(ctx, c, o)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) >= o.Healthy {
			backoff = o.MinBackoff
		}
		if err := o.Sleep(ctx, backoff); err != nil {
			return nil
		}
		backoff *= 2
		if backoff > o.MaxBackoff {
			backoff = o.MaxBackoff
		}
	}
}

func once(ctx context.Context, c Child, o Options) error {
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", c.Unit, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if c.Ready != nil {
		go func() { _ = c.Ready(rctx) }()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	if c.Stop != nil && c.Stop() == nil {
		t := time.NewTimer(o.StopGrace)
		defer t.Stop()
		select {
		case err := <-done:
			return err
		case <-t.C:
		}
	}
	_ = cmd.Process.Kill()
	return <-done
}
