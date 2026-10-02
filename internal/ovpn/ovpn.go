package ovpn

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"time"
)

var ErrBadName = errors.New("invalid common name")

type Client struct {
	Socket  string
	Timeout time.Duration
}

func (c *Client) dial() (net.Conn, error) {
	t := c.Timeout
	if t == 0 {
		t = 3 * time.Second
	}
	conn, err := net.DialTimeout("unix", c.Socket, t)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(t))
	return conn, nil
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

type Params struct {
	Host     string
	Port     int
	Proto    string
	CA       []byte
	Cert     []byte
	TLSCrypt []byte
}
