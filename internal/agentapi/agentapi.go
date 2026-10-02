package agentapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"
)

const (
	OpApply     = "apply"
	OpTLS       = "tls"
	OpStatus    = "status"
	OpDNSUpdate = "dns-update"
	OpRestart   = "restart"
	OpPing      = "ping"
	OpUpdate    = "update"
)

const (
	StatusRun  = "run"
	StatusOK   = "ok"
	StatusFail = "fail"
	StatusSkip = "skip"
)

type Request struct {
	Op  string `json:"op"`
	Arg string `json:"arg,omitempty"`
}

type Event struct {
	Step   string            `json:"step,omitempty"`
	Status string            `json:"status,omitempty"`
	Detail string            `json:"detail,omitempty"`
	Data   map[string]string `json:"data,omitempty"`
	Done   bool              `json:"done,omitempty"`
	Error  string            `json:"error,omitempty"`
}

type Client interface {
	Do(ctx context.Context, req Request, fn func(Event)) error
}

type SocketClient struct {
	Path string
}

var ErrAgent = errors.New("agent failed")

func (c SocketClient) Do(ctx context.Context, req Request, fn func(Event)) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return err
		}
		if fn != nil {
			fn(ev)
		}
		if ev.Done {
			if ev.Error != "" {
				return errors.Join(ErrAgent, errors.New(ev.Error))
			}
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("agent closed connection")
}
