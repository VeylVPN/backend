package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Probe interface {
	DNS(ctx context.Context, server, name string) error
	Health(ctx context.Context, host string, insecure bool) error
	PublicIP(ctx context.Context, v6 bool) (string, error)
	CertExpiry(ctx context.Context, host string) (time.Time, error)
}

type NetProbe struct{}

func (NetProbe) DNS(ctx context.Context, server, name string) error {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := r.LookupIPAddr(c, name)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("empty answer")
	}
	return nil
}

func localTLSClient(host string, insecure bool) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", "127.0.0.1:443")
		},
		TLSClientConfig:   &tls.Config{ServerName: strings.Trim(host, "[]"), InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (NetProbe) Health(ctx context.Context, host string, insecure bool) error {
	url := "https://" + hostPort(host) + "/v1/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := localTLSClient(host, insecure).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ok") {
		return fmt.Errorf("health returned %d", resp.StatusCode)
	}
	return nil
}

func hostPort(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func (NetProbe) CertExpiry(ctx context.Context, host string) (time.Time, error) {
	d := tls.Dialer{Config: &tls.Config{ServerName: strings.Trim(host, "[]"), InsecureSkipVerify: true}}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(c, "tcp", "127.0.0.1:443")
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, errors.New("no certificate")
	}
	return certs[0].NotAfter, nil
}

func fetchIP(ctx context.Context, url string, v6 bool) (string, error) {
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "veyl")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	ip := net.ParseIP(strings.TrimSpace(string(b)))
	if resp.StatusCode != http.StatusOK || ip == nil || (ip.To4() == nil) != v6 {
		return "", errors.New("no address")
	}
	return ip.String(), nil
}

func localGlobal(v6 bool) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || (n.IP.To4() == nil) != v6 {
			continue
		}
		if n.IP.IsGlobalUnicast() && !n.IP.IsPrivate() && !n.IP.IsLoopback() {
			return n.IP.String()
		}
	}
	return ""
}

func (NetProbe) PublicIP(ctx context.Context, v6 bool) (string, error) {
	urls := []string{"https://api.ipify.org", "https://ifconfig.co/ip"}
	if v6 {
		urls = []string{"https://api6.ipify.org", "https://ifconfig.co/ip"}
	}
	var got []string
	for _, u := range urls {
		if ip, err := fetchIP(ctx, u, v6); err == nil {
			got = append(got, ip)
		}
	}
	local := localGlobal(v6)
	switch {
	case len(got) == 2 && got[0] == got[1]:
		return got[0], nil
	case len(got) == 2 && local != "" && (local == got[0] || local == got[1]):
		return local, nil
	case len(got) >= 1:
		return got[0], nil
	case local != "":
		return local, nil
	}
	return "", errors.New("public address not found")
}
