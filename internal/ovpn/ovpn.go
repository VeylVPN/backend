package ovpn

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var (
	ErrBadName     = errors.New("invalid common name")
	ErrAddress     = errors.New("management address must be a unix socket or tcp:127.0.0.1:port")
	ErrPassword    = errors.New("management password rejected")
	ErrNoPassword  = errors.New("management password missing")
	passwordPrompt = []byte("ENTER PASSWORD:")
)

const TCPPrefix = "tcp:"

type Client struct {
	Socket       string
	PasswordFile string
	Password     string
	Timeout      time.Duration
}

type mconn struct {
	net.Conn
	r *bufio.Reader
}

func (m *mconn) Read(p []byte) (int, error) { return m.r.Read(p) }

func tcpAddr(s string) (string, bool) {
	addr, ok := strings.CutPrefix(s, TCPPrefix)
	if !ok {
		return "", false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "", false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", false
	}
	return addr, true
}

func (c *Client) password() (string, error) {
	if c.Password != "" {
		return c.Password, nil
	}
	if c.PasswordFile == "" {
		return "", ErrNoPassword
	}
	f, err := os.Open(c.PasswordFile)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(io.LimitReader(f, 512)).ReadString('\n')
	if err != nil && line == "" {
		return "", ErrNoPassword
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" || strings.ContainsAny(pw, "\r\n\x00") {
		return "", ErrNoPassword
	}
	return pw, nil
}

func login(conn net.Conn, r *bufio.Reader, pw string) error {
	var seen []byte
	for !strings.HasSuffix(string(seen), string(passwordPrompt)) {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		seen = append(seen, b)
		if len(seen) > 512 {
			return ErrPassword
		}
	}
	if _, err := conn.Write([]byte(pw + "\n")); err != nil {
		return err
	}
	var buf []byte
	for len(buf) < 1024 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		buf = append(buf, b)
		if strings.HasSuffix(string(buf), string(passwordPrompt)) {
			return ErrPassword
		}
		if b != '\n' {
			continue
		}
		line := strings.TrimSpace(string(buf))
		buf = buf[:0]
		if strings.HasPrefix(line, "SUCCESS:") {
			return nil
		}
		if strings.HasPrefix(line, "ERROR:") {
			return ErrPassword
		}
	}
	return ErrPassword
}

func (c *Client) dial() (net.Conn, error) {
	t := c.Timeout
	if t == 0 {
		t = 3 * time.Second
	}
	network, addr := "unix", c.Socket
	tcp := strings.HasPrefix(c.Socket, TCPPrefix)
	if tcp {
		a, ok := tcpAddr(c.Socket)
		if !ok {
			return nil, ErrAddress
		}
		network, addr = "tcp", a
	}
	var pw string
	if tcp {
		var err error
		if pw, err = c.password(); err != nil {
			return nil, err
		}
	}
	conn, err := net.DialTimeout(network, addr, t)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(t))
	r := bufio.NewReader(conn)
	if tcp {
		if err := login(conn, r, pw); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return &mconn{Conn: conn, r: r}, nil
}

func (c *Client) State() (string, error) {
	conn, err := c.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("state\n")); err != nil {
		return "", err
	}
	sc := bufio.NewScanner(conn)
	state := ""
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "END" {
			_, _ = conn.Write([]byte("exit\n"))
			return state, nil
		}
		if strings.HasPrefix(line, ">") || strings.HasPrefix(line, "ERROR:") {
			continue
		}
		if f := strings.Split(line, ","); len(f) >= 2 && state == "" {
			state = f[1]
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("management closed")
}

func (c *Client) Online() (map[string]bool, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("status 3\n")); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "END" {
			_, _ = conn.Write([]byte("exit\n"))
			return out, nil
		}
		if strings.HasPrefix(line, "CLIENT_LIST\t") {
			f := strings.Split(line, "\t")
			if len(f) > 1 && f[1] != "" {
				out[f[1]] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("management closed")
}

func validName(cn string) bool {
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

func (c *Client) Kill(cn string) error {
	if !validName(cn) {
		return ErrBadName
	}
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("kill " + cn + "\n")); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "SUCCESS:") {
			_, _ = conn.Write([]byte("exit\n"))
			return nil
		}
		if strings.HasPrefix(line, "ERROR:") {
			_, _ = conn.Write([]byte("exit\n"))
			return errors.New("not connected")
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("management closed")
}

func (c *Client) Signal(sig string) error {
	switch sig {
	case "SIGTERM", "SIGHUP", "SIGUSR1":
	default:
		return errors.New("unsupported signal")
	}
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("signal " + sig + "\n")); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "SUCCESS:") {
			return nil
		}
		if strings.HasPrefix(line, "ERROR:") {
			return errors.New(line)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("management closed")
}
