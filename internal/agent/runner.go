package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

const maxOutput = 256 << 10

type capped struct {
	buf bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !validCommand(name) {
		return nil, errors.New("invalid command")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = runnerEnv()
	var out capped
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil && err != nil {
		err = fmt.Errorf("%s timed out: %w", name, ctx.Err())
	}
	return out.buf.Bytes(), err
}

func validCommand(name string) bool {
	if name == "" || strings.ContainsAny(name, "\t\r\n\x00\"") {
		return false
	}
	if strings.Contains(name, " ") {
		return len(name) > 3 && name[1] == ':' && name[2] == '\\'
	}
	return true
}

const (
	quick   = 20 * time.Second
	service = 120 * time.Second
	slow    = 10 * time.Minute
)

func (a *Agent) run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := a.Runner.Run(c, name, args...)
	if err != nil {
		return string(out), &cmdError{cmd: name + " " + strings.Join(args, " "), out: tail(string(out)), err: err}
	}
	return string(out), nil
}

type cmdError struct {
	cmd string
	out string
	err error
}

func (e *cmdError) Error() string {
	if e.out != "" {
		return e.cmd + ": " + e.out
	}
	return e.cmd + ": " + e.err.Error()
}

func (e *cmdError) Unwrap() error { return e.err }

func tail(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	s = strings.Join(lines, " | ")
	if len(s) > 600 {
		s = s[len(s)-600:]
	}
	return s
}

func (a *Agent) systemctl(ctx context.Context, args ...string) error {
	_, err := a.run(ctx, service, "systemctl", args...)
	return err
}

func (a *Agent) active(ctx context.Context, unit string) bool {
	out, _ := a.run(ctx, quick, "systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

func (a *Agent) state(ctx context.Context, unit string) string {
	out, _ := a.run(ctx, quick, "systemctl", "is-active", unit)
	s := strings.TrimSpace(out)
	if s == "" || len(s) > 32 || strings.ContainsAny(s, " \n") {
		return "unknown"
	}
	return s
}
