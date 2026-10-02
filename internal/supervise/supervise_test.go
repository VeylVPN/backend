package supervise

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/render"
)

func TestMain(m *testing.M) {
	switch os.Getenv("VEYL_SUPERVISE_CHILD") {
	case "exit":
		os.Exit(3)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func self(t *testing.T, mode string) Child {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Child{Unit: "test", Path: exe, Args: []string{"-test.run=^$"}, Env: []string{"VEYL_SUPERVISE_CHILD=" + mode}}
}

func TestRestartsWithBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var waits []time.Duration
	starts := 0
	o := Options{
		MinBackoff: time.Second,
		MaxBackoff: 4 * time.Second,
		Healthy:    time.Hour,
		Sleep: func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			defer mu.Unlock()
			waits = append(waits, d)
			if len(waits) >= 5 {
				cancel()
				return ctx.Err()
			}
			return nil
		},
		Started: func(n int) { starts = n },
	}
	if err := Run(ctx, self(t, "exit"), o); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second, 4 * time.Second}
	if len(waits) != len(want) || starts != 5 {
		t.Fatalf("%v %d", waits, starts)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("%v", waits)
		}
	}
}

func TestStopKillsChildAndCallsStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := self(t, "sleep")
	ready := make(chan struct{})
	stopped := make(chan struct{}, 1)
	c.Ready = func(ctx context.Context) error {
		close(ready)
		<-ctx.Done()
		return nil
	}
	c.Stop = func() error {
		stopped <- struct{}{}
		return errors.New("management unreachable")
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, Options{}) }()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("ready hook not called")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("child not killed")
	}
	if len(stopped) != 1 {
		t.Fatal("stop hook not called")
	}
}

func TestMissingBinaryKeepsRetrying(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	err := Run(ctx, Child{Unit: "x", Path: "/nonexistent/veyl-child"}, Options{Sleep: func(ctx context.Context, d time.Duration) error {
		n++
		if n == 3 {
			cancel()
		}
		return ctx.Err()
	}})
	if err != nil || n != 3 {
		t.Fatal(err, n)
	}
	if err := Run(context.Background(), Child{}, Options{}); err != ErrUnit {
		t.Fatal(err)
	}
}

func TestSpecs(t *testing.T) {
	for unit, want := range map[string]string{
		UnitOpenVPNUDP: config.WinOpenVPNBin + " --config " + render.WinOpenVPNPath(config.InstanceUDP),
		UnitOpenVPNTCP: config.WinOpenVPNBin + " --config " + render.WinOpenVPNPath(config.InstanceTCP),
		UnitUnbound:    `C:\Program Files\Veyl\unbound\unbound.exe -d -c C:\ProgramData\Veyl\unbound\unbound.conf`,
		UnitCaddy:      `C:\Program Files\Veyl\caddy\caddy.exe run --config C:\ProgramData\Veyl\caddy\Caddyfile --adapter caddyfile`,
	} {
		c, err := Spec(unit)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.Path + " " + strings.Join(c.Args, " "); got != want {
			t.Errorf("%s: %s", unit, got)
		}
		for _, a := range c.Args {
			if strings.Contains(a, "log") {
				t.Errorf("%s writes a log: %v", unit, c.Args)
			}
		}
	}
	c, _ := Spec(UnitCaddy)
	if strings.Join(c.Env, " ") != `XDG_DATA_HOME=C:\ProgramData\Veyl\caddy\data XDG_CONFIG_HOME=C:\ProgramData\Veyl\caddy\config` {
		t.Fatal(c.Env)
	}
	if _, err := Spec("cmd.exe"); err != ErrUnit {
		t.Fatal(err)
	}
}

type fakeState struct {
	states []string
}

func (f *fakeState) State() (string, error) {
	if len(f.states) == 0 {
		return "", errors.New("down")
	}
	s := f.states[0]
	f.states = f.states[1:]
	return s, nil
}

func TestWaitConnected(t *testing.T) {
	sleep := func(ctx context.Context, d time.Duration) error { return nil }
	if err := WaitConnected(context.Background(), &fakeState{states: []string{"CONNECTING", "ASSIGN_IP", "CONNECTED"}}, sleep, 5); err != nil {
		t.Fatal(err)
	}
	if err := WaitConnected(context.Background(), &fakeState{}, sleep, 3); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestMainRefusesOutsideWindows(t *testing.T) {
	var b strings.Builder
	if config.Platform == config.PlatformWindows {
		t.Skip("windows host")
	}
	if Main([]string{"caddy"}, &b) != 2 || Main(nil, &b) != 2 {
		t.Fatal(b.String())
	}
}
