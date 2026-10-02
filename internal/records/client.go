package records

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

var (
	ErrNXDomain = errors.New("no such domain")
	ErrServer   = errors.New("dns server error")
	ErrLoop     = errors.New("cname chain too long")
)

type Client struct {
	Timeout time.Duration
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (c *Client) timeout() time.Duration {
	if c == nil || c.Timeout <= 0 {
		return 3 * time.Second
	}
	return c.Timeout
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c != nil && c.Dial != nil {
		return c.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func newID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint16(b[:])
}

func matches(msg *Msg, id uint16, name string, qtype uint16) bool {
	if !msg.Response || msg.ID != id || len(msg.Question) != 1 {
		return false
	}
	q := msg.Question[0]
	return q.Name == name && q.Type == qtype && q.Class == classIN
}

func (c *Client) Exchange(ctx context.Context, server, name string, qtype uint16, recursion bool) (*Msg, error) {
	n, err := CanonicalName(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	msg, err := c.exchangeUDP(ctx, server, n, qtype, recursion)
	if err == nil && msg.Truncated {
		return c.exchangeTCP(ctx, server, n, qtype, recursion)
	}
	return msg, err
}

func (c *Client) exchangeUDP(ctx context.Context, server, name string, qtype uint16, recursion bool) (*Msg, error) {
	id := newID()
	q, err := BuildQuery(id, name, qtype, recursion)
	if err != nil {
		return nil, err
	}
	conn, err := c.dial(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		k, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		msg, perr := Parse(buf[:k])
		if perr != nil || !matches(msg, id, name, qtype) {
			continue
		}
		return msg, nil
	}
}

func (c *Client) exchangeTCP(ctx context.Context, server, name string, qtype uint16, recursion bool) (*Msg, error) {
	id := newID()
	q, err := BuildQuery(id, name, qtype, recursion)
	if err != nil {
		return nil, err
	}
	conn, err := c.dial(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	frame := make([]byte, 2, 2+len(q))
	binary.BigEndian.PutUint16(frame, uint16(len(q)))
	if _, err := conn.Write(append(frame, q...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint16(lb[:]))
	if l < 12 {
		return nil, ErrFormat
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	msg, err := Parse(buf)
	if err != nil {
		return nil, err
	}
	if msg.Truncated || !matches(msg, id, name, qtype) {
		return nil, ErrFormat
	}
	return msg, nil
}

type Answer struct {
	Name    string
	Records []RR
	CNAMEs  []string
	TTL     uint32
	Auth    bool
}

func checkRcode(msg *Msg) error {
	switch msg.Rcode {
	case RcodeOK:
		return nil
	case RcodeNXDomain:
		return ErrNXDomain
	}
	return ErrServer
}

func (c *Client) Lookup(ctx context.Context, server, name string, qtype uint16, recursion bool) (Answer, error) {
	n, err := CanonicalName(name)
	if err != nil {
		return Answer{}, err
	}
	out := Answer{Name: n}
	cur := n
	for hop := 0; hop < 8; hop++ {
		msg, err := c.Exchange(ctx, server, cur, qtype, recursion)
		if err != nil {
			return out, err
		}
		out.Auth = msg.Authority
		if err := checkRcode(msg); err != nil {
			return out, err
		}
		owner := cur
		for i := 0; i < 8; i++ {
			next := ""
			for _, rr := range msg.Answer {
				if rr.Class == classIN && rr.Type == TypeCNAME && rr.Name == owner && qtype != TypeCNAME {
					next = rr.Target
					setTTL(&out, rr.TTL)
					break
				}
			}
			if next == "" {
				break
			}
			out.CNAMEs = append(out.CNAMEs, next)
			owner = next
		}
		for _, rr := range msg.Answer {
			if rr.Class == classIN && rr.Type == qtype && rr.Name == owner {
				out.Records = append(out.Records, rr)
				setTTL(&out, rr.TTL)
			}
		}
		if len(out.Records) > 0 || owner == cur {
			return out, nil
		}
		cur = owner
	}
	return out, ErrLoop
}

func setTTL(a *Answer, ttl uint32) {
	if a.TTL == 0 || ttl < a.TTL {
		a.TTL = ttl
	}
}

func Parent(name string) string {
	_, rest, ok := strings.Cut(name, ".")
	if !ok || rest == "" {
		return ""
	}
	return rest
}
