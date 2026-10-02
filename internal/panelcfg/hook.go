package panelcfg

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"
)

const (
	HookAuth    = "auth"
	HookCleanup = "cleanup"
	HookWait    = 45 * time.Minute
)

type HookRequest struct {
	Op         string `json:"op"`
	Domain     string `json:"domain"`
	Validation string `json:"validation"`
}

type HookReply struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func ValidValidation(v string) bool {
	if len(v) < 16 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (r HookRequest) Validate() error {
	if r.Op != HookAuth && r.Op != HookCleanup {
		return errors.New("unknown hook operation")
	}
	if !ValidDomain(r.Domain) {
		return ErrDomain
	}
	if !ValidValidation(r.Validation) {
		return errors.New("invalid validation token")
	}
	return nil
}

func AskHook(ctx context.Context, sock string, req HookRequest) (HookReply, error) {
	if err := req.Validate(); err != nil {
		return HookReply{}, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return HookReply{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return HookReply{}, err
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 4096), 4096)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return HookReply{}, err
		}
		return HookReply{}, errors.New("panel closed the connection")
	}
	var rep HookReply
	if err := json.Unmarshal(sc.Bytes(), &rep); err != nil {
		return HookReply{}, err
	}
	return rep, nil
}
