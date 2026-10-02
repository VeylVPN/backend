package dns

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/veylvpn/backend/internal/config"
)

func TestRunServesAndStops(t *testing.T) {
	up := newFakeUpstream(t)
	dir := t.TempDir()
	writeFile(t, ListPath(dir, config.CatTrackers), "track.example.com\n", time.Unix(1700000000, 0))
	ctx, cancel := context.WithCancel(context.Background())
	addrs := make(chan []string, 1)
	code := make(chan int, 1)
	var stderr bytes.Buffer
	go func() {
		code <- run(ctx, []string{
			"-blocklists", dir,
			"-upstream", up.addr,
			"-listen-test", "127.0.0.1:0",
			"-test-mask", "2",
		}, &stderr, func(s *Server) { addrs <- s.Addrs() })
	}()
	var a []string
	select {
	case a = <-addrs:
	case c := <-code:
		t.Fatalf("run exited %d: %s", c, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("not ready")
	}
	r, err := udpExchange(t, a[0], buildQuery(1, "x.track.example.com", typeA, false), 2*time.Second)
	if err != nil || !isBlockedA(mustParse(t, r)) {
		t.Fatalf("tracker not blocked: %v", err)
	}
	rs := tcpExchange(t, a[0], buildQuery(2, "fine.example.com", typeA, false))
	if !isForwardedA(mustParse(t, rs[0])) {
		t.Fatal("not forwarded")
	}
	cancel()
	select {
	case c := <-code:
		if c != 0 {
			t.Fatalf("exit %d", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop")
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected output: %q", stderr.String())
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-upstream", "not-an-addr"},
		{"-count", "65"},
		{"-prefix", "10.64"},
		{"-listen-test", "nope"},
		{"-listen-test", "127.0.0.1:0", "-test-mask", "64"},
		{"-unknown"},
	} {
		var stderr bytes.Buffer
		if c := run(context.Background(), args, &stderr, nil); c != 2 {
			t.Fatalf("%v exit %d", args, c)
		}
	}
}

func TestRunListenFailure(t *testing.T) {
	var stderr bytes.Buffer
	if c := run(context.Background(), []string{"-blocklists", t.TempDir(), "-listen-test", "192.0.2.1:0"}, &stderr, nil); c != 1 {
		t.Fatalf("exit %d", c)
	}
}
