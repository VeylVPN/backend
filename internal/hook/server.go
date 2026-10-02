package hook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/hookapi"
)

const (
	maxRequest  = 4 << 10
	maxParallel = 64
	connTimeout = 5 * time.Second
	SocketGroup = "veyl"
)

type Server struct {
	d     app.Deps
	Group string
	now   func() time.Time
}

func NewServer(d app.Deps) *Server {
	return &Server{d: d, Group: SocketGroup, now: time.Now}
}

func ValidCN(cn string) bool {
	if cn == "" || len(cn) > 64 {
		return false
	}
	for _, r := range cn {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func (s *Server) Decide(req hookapi.Request) hookapi.Response {
	deny := hookapi.Response{Allow: false}
	switch req.Event {
	case hookapi.EventDisconnect:
		return hookapi.Response{Allow: true}
	case hookapi.EventVerify, hookapi.EventConnect:
	default:
		return deny
	}
	if !ValidCN(req.CN) {
		return deny
	}
	acc, _, ok := s.d.Store.LookupDevice(req.CN)
	if !ok {
		return deny
	}
	if acc.Active(s.now().Unix()) != nil {
		return deny
	}
	if req.Event == hookapi.EventVerify {
		return hookapi.Response{Allow: true}
	}
	if s.d.Settings == nil {
		return deny
	}
	set := s.d.Settings.Get()
	cats := acc.DNSCategories(set.DNS.Default)
	if !config.ValidCategories(cats) {
		return deny
	}
	return hookapi.Response{Allow: true, Push: []string{"dhcp-option DNS " + config.DNSAddr(cats)}}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(connTimeout))
	var req hookapi.Request
	resp := hookapi.Response{Allow: false}
	dec := json.NewDecoder(io.LimitReader(c, maxRequest))
	if err := dec.Decode(&req); err == nil {
		resp = s.Decide(req)
	}
	_ = json.NewEncoder(c).Encode(resp)
}

func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("hook socket path exists and is not a socket")
	}
	return os.Remove(path)
}

func (s *Server) chgrp(path string) error {
	if s.Group == "" {
		return nil
	}
	g, err := user.LookupGroup(s.Group)
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, -1, gid)
}

func (s *Server) Serve(ctx context.Context, socketPath string) error {
	if err := removeStale(socketPath); err != nil {
		return err
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(socketPath)
	defer l.Close()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return err
	}
	if err := s.chgrp(socketPath); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handle(c)
		}()
	}
}
