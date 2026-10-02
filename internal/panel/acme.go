package panel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/records"
	"github.com/veylvpn/backend/internal/web"
)

type Challenge struct {
	Domain  string            `json:"domain"`
	Name    string            `json:"name"`
	Value   string            `json:"value"`
	Started int64             `json:"started"`
	Status  string            `json:"status"`
	Report  records.TXTReport `json:"report"`
	Record  records.Record    `json:"record"`
}

type ACMEHub struct {
	p      *panelcfg.Paths
	panel  *Panel
	Every  time.Duration
	Wait   time.Duration
	mu     sync.Mutex
	cur    *Challenge
	cancel context.CancelFunc
}

func newACMEHub(p *Panel) *ACMEHub {
	return &ACMEHub{panel: p, Every: 5 * time.Second, Wait: panelcfg.HookWait}
}

func (h *ACMEHub) Current() *Challenge {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur == nil {
		return nil
	}
	c := *h.cur
	return &c
}

func (h *ACMEHub) Cancel() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cancel == nil {
		return false
	}
	h.cancel()
	return true
}

func (h *ACMEHub) Listen(sock string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(sock), 0o770); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errors.New(sock + " exists and is not a socket")
		}
		_ = os.Remove(sock)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o600)
	return ln, nil
}

func (h *ACMEHub) Serve(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		go h.handle(ctx, c)
	}
}

func (h *ACMEHub) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	reply := func(r panelcfg.HookReply) {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = json.NewEncoder(c).Encode(r)
	}
	root := peerIsRoot(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReaderSize(io.LimitReader(c, 4096), 4096).ReadSlice('\n')
	if !root {
		reply(panelcfg.HookReply{Message: "forbidden"})
		return
	}
	if err != nil {
		reply(panelcfg.HookReply{Message: "bad request"})
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req panelcfg.HookRequest
	if json.Unmarshal(line, &req) != nil || req.Validate() != nil {
		reply(panelcfg.HookReply{Message: "bad request"})
		return
	}
	if req.Domain != h.panel.site().Domain {
		reply(panelcfg.HookReply{Message: "not the panel domain"})
		return
	}
	switch req.Op {
	case panelcfg.HookCleanup:
		h.mu.Lock()
		if h.cur != nil && h.cur.Value == req.Validation {
			h.cur = nil
		}
		h.mu.Unlock()
		reply(panelcfg.HookReply{OK: true})
	case panelcfg.HookAuth:
		err := h.Authorize(ctx, req.Domain, req.Validation)
		if err != nil {
			reply(panelcfg.HookReply{Message: err.Error()})
			return
		}
		reply(panelcfg.HookReply{OK: true})
	}
}

func (h *ACMEHub) Authorize(ctx context.Context, domain, value string) error {
	name := panelcfg.ChallengeName(domain)
	wctx, cancel := context.WithTimeout(ctx, h.Wait)
	defer cancel()
	ch := &Challenge{Domain: domain, Name: name, Value: value, Started: h.panel.now().Unix(), Status: "waiting"}
	h.mu.Lock()
	if h.cancel != nil {
		h.cancel()
	}
	h.cur = ch
	h.cancel = cancel
	h.mu.Unlock()
	if h.panel.job("cert") == nil || !h.panel.job("cert").Running() {
		h.panel.alerts.Emit(Event{Kind: EventCertExpiring, Subject: "panel", Title: "Certificate renewal needs a DNS record", Message: "Add the TXT record " + name + " with value " + value + " so the panel certificate can renew. Open Domains in Veyl Control to follow along."})
	}
	err := h.panel.opt.Checker.WaitTXT(wctx, name, value, h.Every, func(r records.TXTReport) {
		h.mu.Lock()
		if h.cur == ch {
			ch.Report = r
			ch.Record = r.Record
		}
		h.mu.Unlock()
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur == ch {
		h.cancel = nil
		if err != nil {
			ch.Status = "cancelled"
		} else {
			ch.Status = "visible"
		}
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("the TXT record did not show up in time")
		}
		return errors.New("cancelled")
	}
	return nil
}

func (p *Panel) challengeState(w http.ResponseWriter, r *http.Request) {
	c := p.acme.Current()
	if c == nil {
		web.JSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if c.Record.Line == "" {
		c.Record = records.Record{Name: c.Name, Type: "TXT", Value: c.Value, TTL: records.SuggestedTTL, Action: "add", Line: c.Name + ". 300 IN TXT \"" + c.Value + "\""}
	}
	web.JSON(w, http.StatusOK, map[string]any{"active": true, "challenge": c})
}

func (p *Panel) challengeCancel(w http.ResponseWriter, r *http.Request) {
	web.JSON(w, http.StatusOK, map[string]bool{"cancelled": p.acme.Cancel()})
}
