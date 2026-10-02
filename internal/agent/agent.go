package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
)

var DownloadBlocklists func(ctx context.Context, dir string, client *http.Client) (map[string]int, error)

type Agent struct {
	Root          string
	Paths         config.Paths
	Runner        Runner
	Probe         Probe
	HTTP          *http.Client
	Download      func(ctx context.Context, dir string, client *http.Client) (map[string]int, error)
	Lookup        func(name string) (uid, gid int, err error)
	Chown         func(path string, uid, gid int) error
	AllowUID      func(uid uint32) bool
	Sleep         func(ctx context.Context, d time.Duration) error
	HealthTimeout time.Duration
	VerifyTimeout time.Duration
	Windows       bool
	Async         func(func())
	MgmtState     func(instance string) (string, error)

	once sync.Once
	lock chan struct{}
}

func New() *Agent {
	return &Agent{
		Paths:   config.DefaultPaths(),
		Runner:  ExecRunner{},
		Probe:   NetProbe{},
		HTTP:    &http.Client{Timeout: 90 * time.Second},
		Windows: config.Platform == config.PlatformWindows,
	}
}

func (a *Agent) init() {
	a.once.Do(func() {
		a.lock = make(chan struct{}, 1)
		if a.Runner == nil {
			a.Runner = ExecRunner{}
		}
		if a.Probe == nil {
			a.Probe = NetProbe{}
		}
		if a.HTTP == nil {
			a.HTTP = &http.Client{Timeout: 90 * time.Second}
		}
		if a.Paths.Data == "" {
			a.Paths = config.DefaultPaths()
		}
		if a.Lookup == nil {
			a.Lookup = lookupUser
		}
		if a.Chown == nil {
			a.Chown = os.Lchown
		}
		if a.Sleep == nil {
			a.Sleep = sleepCtx
		}
		if a.HealthTimeout == 0 {
			a.HealthTimeout = 120 * time.Second
		}
		if a.VerifyTimeout == 0 {
			a.VerifyTimeout = 30 * time.Second
		}
		if a.Async == nil {
			a.Async = func(fn func()) { go fn() }
		}
	})
}

func (a *Agent) download() func(ctx context.Context, dir string, client *http.Client) (map[string]int, error) {
	if a.Download != nil {
		return a.Download
	}
	return DownloadBlocklists
}

func lookupUser(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (a *Agent) path(p string) string {
	if a.Root == "" {
		return p
	}
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' {
		p = strings.ReplaceAll(p[2:], `\`, "/")
	}
	return filepath.Join(a.Root, p)
}

func (a *Agent) allowed(uid uint32) bool {
	if a.AllowUID != nil {
		return a.AllowUID(uid)
	}
	if uid == 0 {
		return true
	}
	u, _, err := a.Lookup(config.ServiceUser)
	return err == nil && uint32(u) == uid
}

var (
	ErrUnknownOp = errors.New("unknown operation")
	ErrBusy      = errors.New("another operation is still running")
	errSkip      = errors.New("skipped")
)

type skipError struct{ msg string }

func (e skipError) Error() string { return e.msg }
func (e skipError) Is(t error) bool {
	return t == errSkip
}

func skip(format string, a ...any) error {
	return skipError{msg: fmt.Sprintf(format, a...)}
}

type Emit func(agentapi.Event)

func mutating(op string) bool {
	switch op {
	case agentapi.OpApply, agentapi.OpTLS, agentapi.OpDNSUpdate, agentapi.OpRestart:
		return true
	}
	return false
}

func (a *Agent) Do(ctx context.Context, op string, emit Emit) (map[string]string, error) {
	a.init()
	if emit == nil {
		emit = func(agentapi.Event) {}
	}
	if a.Windows {
		return a.doWindows(ctx, op, emit)
	}
	switch op {
	case agentapi.OpPing:
		return map[string]string{"pong": "1"}, nil
	case agentapi.OpStatus:
		return a.Status(ctx)
	}
	if !mutating(op) {
		return nil, ErrUnknownOp
	}
	if err := a.acquire(ctx, emit); err != nil {
		return nil, err
	}
	defer a.release()
	switch op {
	case agentapi.OpApply:
		return nil, a.Apply(ctx, emit)
	case agentapi.OpTLS:
		return nil, a.TLS(ctx, emit)
	case agentapi.OpDNSUpdate:
		return a.DNSUpdate(ctx, emit)
	case agentapi.OpRestart:
		return nil, a.Restart(ctx, emit)
	}
	return nil, ErrUnknownOp
}

func (a *Agent) acquire(ctx context.Context, emit Emit) error {
	select {
	case a.lock <- struct{}{}:
		return nil
	default:
	}
	emit(agentapi.Event{Step: "queue", Status: agentapi.StatusRun, Detail: "waiting for the running operation to finish"})
	t := time.NewTimer(30 * time.Minute)
	defer t.Stop()
	select {
	case a.lock <- struct{}{}:
		emit(agentapi.Event{Step: "queue", Status: agentapi.StatusOK})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return ErrBusy
	}
}

func (a *Agent) release() {
	<-a.lock
}

func step(emit Emit, name string, fn func() (string, error)) error {
	emit(agentapi.Event{Step: name, Status: agentapi.StatusRun})
	detail, err := fn()
	if err != nil {
		if errors.Is(err, errSkip) {
			emit(agentapi.Event{Step: name, Status: agentapi.StatusSkip, Detail: err.Error()})
			return nil
		}
		emit(agentapi.Event{Step: name, Status: agentapi.StatusFail, Detail: err.Error()})
		return fmt.Errorf("%s: %w", name, err)
	}
	emit(agentapi.Event{Step: name, Status: agentapi.StatusOK, Detail: detail})
	return nil
}

func (a *Agent) settings() (config.Settings, error) {
	return config.Load(a.path(a.Paths.Settings()))
}
