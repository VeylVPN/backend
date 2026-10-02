package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	DefaultRate  = 200
	DefaultBurst = 400
	maxInflight  = 2048
	maxTCPConns  = 512
	tcpIdle      = 10 * time.Second
	tcpPerConn   = 128
)

type Listener struct {
	Addr string
	Mask int
}

type Options struct {
	Listeners  []Listener
	Upstream   string
	Lists      func() *Lists
	Rate       float64
	Burst      float64
	UDPTimeout time.Duration
	TCPTimeout time.Duration
}

type Server struct {
	opts    Options
	limiter *limiter
	sem     chan struct{}
	tcpSem  chan struct{}
	udp     []*net.UDPConn
	tcp     []*net.TCPListener
	masks   []int
	wg      sync.WaitGroup
}

func NewServer(o Options) *Server {
	if o.UDPTimeout <= 0 {
		o.UDPTimeout = 2 * time.Second
	}
	if o.TCPTimeout <= 0 {
		o.TCPTimeout = 5 * time.Second
	}
	if o.Lists == nil {
		o.Lists = func() *Lists { return nil }
	}
	return &Server{
		opts:    o,
		limiter: newLimiter(o.Rate, o.Burst),
		sem:     make(chan struct{}, maxInflight),
		tcpSem:  make(chan struct{}, maxTCPConns),
	}
}

func (s *Server) Listen() error {
	for _, l := range s.opts.Listeners {
		u, t, err := listenPair(l.Addr)
		if err != nil {
			s.closeAll()
			return err
		}
		s.udp = append(s.udp, u)
		s.tcp = append(s.tcp, t)
		s.masks = append(s.masks, l.Mask)
	}
	return nil
}

func listenPair(addr string) (*net.UDPConn, *net.TCPListener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	tries := 1
	if port == "0" {
		tries = 20
	}
	var last error
	for i := 0; i < tries; i++ {
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, nil, err
		}
		u, err := net.ListenUDP("udp", ua)
		if err != nil {
			return nil, nil, fmt.Errorf("listen udp %s: %w", addr, err)
		}
		p := u.LocalAddr().(*net.UDPAddr).Port
		ta, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, fmt.Sprint(p)))
		if err != nil {
			u.Close()
			return nil, nil, err
		}
		t, err := net.ListenTCP("tcp", ta)
		if err == nil {
			return u, t, nil
		}
		u.Close()
		last = fmt.Errorf("listen tcp %s: %w", ta, err)
	}
	return nil, nil, last
}

func (s *Server) Addrs() []string {
	out := make([]string, len(s.udp))
	for i, u := range s.udp {
		out[i] = u.LocalAddr().String()
	}
	return out
}

func (s *Server) closeAll() {
	for _, u := range s.udp {
		u.Close()
	}
	for _, t := range s.tcp {
		t.Close()
	}
}

func (s *Server) Serve(ctx context.Context) error {
	if len(s.udp) == 0 {
		return errors.New("no listeners")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := range s.udp {
		s.wg.Add(2)
		go s.serveUDP(s.udp[i], s.masks[i])
		go s.serveTCP(ctx, s.tcp[i], s.masks[i])
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.closeAll()
			s.wg.Wait()
			return nil
		case <-t.C:
			s.limiter.prune()
		}
	}
}

func (s *Server) serveUDP(c *net.UDPConn, mask int) {
	defer s.wg.Done()
	buf := make([]byte, maxUDP+1)
	for {
		n, src, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < headerLen || n > maxUDP {
			continue
		}
		if !s.limiter.allow(src.Addr()) {
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			if resp := s.handle(pkt, mask, false); resp != nil {
				c.WriteToUDPAddrPort(resp, src)
			}
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, l *net.TCPListener, mask int) {
	defer s.wg.Done()
	for {
		c, err := l.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		select {
		case s.tcpSem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.tcpSem }()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			s.handleConn(c, mask)
		}()
	}
}

func (s *Server) handleConn(c *net.TCPConn, mask int) {
	defer c.Close()
	src := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
	var lb [2]byte
	for i := 0; i < tcpPerConn; i++ {
		c.SetReadDeadline(time.Now().Add(tcpIdle))
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < headerLen || n > maxUDP {
			return
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		var resp []byte
		if s.limiter.allow(src) {
			resp = s.handle(pkt, mask, true)
		} else if q, err := ParseQuery(pkt); err == nil {
			resp = refusedReply(pkt, q)
		}
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		c.SetWriteDeadline(time.Now().Add(s.opts.TCPTimeout))
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func (s *Server) handle(pkt []byte, mask int, tcp bool) []byte {
	q, err := ParseQuery(pkt)
	if err != nil {
		return nil
	}
	if q.Plain && s.opts.Lists().Blocked(q.Name, mask) {
		return BlockedReply(pkt, q)
	}
	if tcp {
		resp, err := s.forwardTCP(pkt, q.ID)
		if err != nil {
			return nil
		}
		return resp
	}
	resp, err := s.forwardUDP(pkt, q.ID)
	if err != nil {
		return nil
	}
	limit := q.ClientUDPSize()
	if resp[2]&byte(flagTC>>8) != 0 {
		if full, err := s.forwardTCP(pkt, q.ID); err == nil && len(full) <= limit {
			return full
		}
	}
	if len(resp) > limit {
		return truncatedReply(pkt, q)
	}
	return resp
}

func (s *Server) forwardUDP(pkt []byte, id uint16) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := s.exchangeUDP(pkt, id)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

func (s *Server) exchangeUDP(pkt []byte, id uint16) ([]byte, error) {
	c, err := net.Dial("udp", s.opts.Upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(s.opts.UDPTimeout))
	if _, err := c.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, maxMsg)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if validResponse(buf[:n], id) {
			out := make([]byte, n)
			copy(out, buf[:n])
			return out, nil
		}
	}
}

func (s *Server) forwardTCP(pkt []byte, id uint16) ([]byte, error) {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := s.exchangeTCP(pkt, id)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

func (s *Server) exchangeTCP(pkt []byte, id uint16) ([]byte, error) {
	c, err := net.DialTimeout("tcp", s.opts.Upstream, s.opts.TCPTimeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(s.opts.TCPTimeout))
	out := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(out, uint16(len(pkt)))
	copy(out[2:], pkt)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if !validResponse(resp, id) {
		return nil, errMalformed
	}
	return resp, nil
}
