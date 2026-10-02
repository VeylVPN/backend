package dns

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/winsvc"
)

const reloadEvery = 60 * time.Second

func Main(args []string) int {
	return run(winsvc.Context(), args, os.Stderr, nil)
}

func run(ctx context.Context, args []string, stderr io.Writer, ready func(*Server)) int {
	fs := flag.NewFlagSet("dns", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("blocklists", config.DefaultPaths().Blocklists(), "blocklist directory")
	upstream := fs.String("upstream", config.UnboundAddr, "upstream resolver host:port")
	prefix := fs.String("prefix", config.DNSPrefix, "first three octets of the listen addresses")
	count := fs.Int("count", config.MaxMask()+1, "number of listen addresses")
	port := fs.Int("port", 53, "listen port")
	fs.String("settings", config.DefaultPaths().Settings(), "settings file")
	listenTest := fs.String("listen-test", "", "listen only on this host:port")
	testMask := fs.Int("test-mask", config.MaxMask(), "category mask for -listen-test")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := netip.ParseAddrPort(*upstream); err != nil {
		fmt.Fprintln(stderr, "dns: invalid -upstream")
		return 2
	}
	var ls []Listener
	if *listenTest != "" {
		if _, _, err := net.SplitHostPort(*listenTest); err != nil || *testMask < 0 || *testMask > config.MaxMask() {
			fmt.Fprintln(stderr, "dns: invalid -listen-test or -test-mask")
			return 2
		}
		ls = []Listener{{Addr: *listenTest, Mask: *testMask}}
	} else {
		var err error
		ls, err = Listeners(*prefix, *count, *port)
		if err != nil {
			fmt.Fprintln(stderr, "dns:", err)
			return 2
		}
	}
	bl := NewBlocklists(*dir)
	if _, err := bl.Reload(true); err != nil {
		fmt.Fprintln(stderr, "dns: blocklists:", err)
	}
	srv := NewServer(Options{
		Listeners: ls,
		Upstream:  *upstream,
		Lists:     bl.Lists,
		Rate:      DefaultRate,
		Burst:     DefaultBurst,
	})
	if err := srv.Listen(); err != nil {
		fmt.Fprintln(stderr, "dns:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go bl.Run(ctx, reloadEvery, hup)
	if ready != nil {
		ready(srv)
	}
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintln(stderr, "dns:", err)
		return 1
	}
	return 0
}

func Listeners(prefix string, count, port int) ([]Listener, error) {
	if count < 1 || count > config.MaxMask()+1 {
		return nil, errors.New("count out of range")
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("port out of range")
	}
	if a, err := netip.ParseAddr(prefix + ".0"); err != nil || !a.Is4() {
		return nil, errors.New("invalid prefix")
	}
	out := make([]Listener, 0, count)
	for n := 1; n <= count; n++ {
		ip := prefix + "." + strconv.Itoa(n)
		mask, ok := config.MaskForAddr(ip)
		if !ok {
			mask = n - 1
		}
		out = append(out, Listener{Addr: net.JoinHostPort(ip, strconv.Itoa(port)), Mask: mask})
	}
	return out, nil
}
