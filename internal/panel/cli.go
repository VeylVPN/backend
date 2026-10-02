package panel

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/panelcfg"
)

func Paths() panelcfg.Paths {
	p := panelcfg.DefaultPaths()
	if v := os.Getenv("VEYL_PANEL_DATA"); v != "" {
		p.Data = v
	}
	if v := os.Getenv("VEYL_PANEL_RUN"); v != "" {
		p.Run = v
	}
	return p
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "veyl panel:", err)
	return 1
}

func HTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

func Serve(args []string) int {
	fs := flag.NewFlagSet("panel serve", flag.ContinueOnError)
	listen := fs.String("listen", panelcfg.Listen, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	paths := Paths()
	httpc := &http.Client{Timeout: 20 * time.Second}
	p, err := New(Options{Paths: paths, Agent: agentapi.SocketClient{Path: paths.AgentSock()}, Releases: GitHubRelease(httpc)})
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail(err)
	}
	srv := HTTPServer(*listen, p.Handler())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	if hl, err := p.acme.Listen(paths.ACMESock()); err == nil {
		go p.acme.Serve(ctx, hl)
	}
	p.Run(ctx)
	_ = Notify("READY=1\nSTATUS=Veyl Control is running")
	go p.watchdog(ctx, "http://"+ln.Addr().String()+"/v1/health")
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fail(err)
		}
	}
	_ = Notify("STOPPING=1")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	return 0
}

func (p *Panel) Healthy(ctx context.Context, url string) bool {
	c := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	res, err := c.Do(req)
	if err != nil {
		return false
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false
	}
	last := p.mon.LastTick()
	return last.IsZero() || p.now().Sub(last) < 5*p.opt.Interval+time.Minute
}

func (p *Panel) watchdog(ctx context.Context, url string) {
	every := WatchdogInterval()
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if p.Healthy(ctx, url) {
				_ = Notify("WATCHDOG=1")
			}
		}
	}
}

func SetupLink(host, token string, https bool) string {
	if https {
		return "https://" + host + "/setup#" + token
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "http://" + host + panelcfg.SetupPrefix + "/setup#" + token
}

func setupLinkMain(args []string) int {
	paths := Paths()
	s, _ := panelcfg.LoadSite(paths.Site())
	if s.Configured {
		fmt.Println("Veyl Control is already set up: https://" + s.Domain + "/")
		return 0
	}
	t, err := NewSetupToken(paths)
	if err != nil {
		return fail(err)
	}
	st := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = agentapi.SocketClient{Path: paths.AgentSock()}.Do(ctx, agentapi.Request{Op: agentapi.OpStatus}, func(ev agentapi.Event) {
		for k, v := range ev.Data {
			st[k] = v
		}
	})
	host := st["public_ipv4"]
	if host == "" {
		host = s.PublicIP
	}
	if host == "" {
		host = "<server-ip>"
	}
	fmt.Println("Open this link to set up Veyl Control:")
	fmt.Println()
	if s.Domain != "" && st["cert_expiry"] != "" {
		fmt.Println("  " + SetupLink(s.Domain, t, true))
	} else {
		fmt.Println("  " + SetupLink(host, t, false))
	}
	fmt.Println()
	return 0
}

func hookMain(op string) int {
	req := panelcfg.HookRequest{Op: op, Domain: os.Getenv("CERTBOT_DOMAIN"), Validation: os.Getenv("CERTBOT_VALIDATION")}
	wait := panelcfg.HookWait + time.Minute
	if op == panelcfg.HookCleanup {
		wait = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	rep, err := panelcfg.AskHook(ctx, Paths().ACMESock(), req)
	if op == panelcfg.HookCleanup {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "veyl panel acme-auth: cannot reach Veyl Control:", err)
		return 1
	}
	if !rep.OK {
		fmt.Fprintln(os.Stderr, "veyl panel acme-auth:", rep.Message)
		return 1
	}
	return 0
}

func RecoverUser(paths panelcfg.Paths, username string) (string, error) {
	db, err := OpenDB(paths.DB())
	if err != nil {
		return "", err
	}
	pw := randToken(15)
	h, err := admin.HashPassword(pw)
	if err != nil {
		return "", err
	}
	err = db.Update(func(d *data) error {
		u := d.userByName(strings.ToLower(username))
		if u == nil {
			return errNoUser
		}
		u.Password, u.TOTP, u.TOTPLast, u.Recovery, u.MustEnroll, u.Epoch = h, "", 0, nil, true, randID()
		keep := d.Sessions[:0]
		for _, s := range d.Sessions {
			if s.UserID != u.ID {
				keep = append(keep, s)
			}
		}
		d.Sessions = keep
		d.Audit = append(d.Audit, AuditEntry{Time: time.Now().Unix(), User: "root", Action: "team.recover", Target: u.Username})
		return nil
	})
	return pw, err
}

func ListUsers(paths panelcfg.Paths) ([]string, error) {
	db, err := OpenDB(paths.DB())
	if err != nil {
		return nil, err
	}
	var out []string
	db.View(func(d *data) {
		for _, u := range d.Users {
			out = append(out, u.Username+" ("+u.Role+")")
		}
	})
	return out, nil
}

const Usage = `usage: veyl panel <command>

  install [-domain D] [-email E]   install Veyl Control on this server
  uninstall [-purge]               remove Veyl Control
  setup-link                       print a fresh setup link
  pair [-scope manage|monitor]     create a pairing code for this VPN node
  recover <username>               reset a panel user's password and two-step sign in
  backup <file>                    write an encrypted panel backup
  restore [-force] <file>          restore an encrypted panel backup
  update                           update Veyl Control
  status                           show panel service health

  serve | agent | acme-auth | acme-cleanup | acme-deploy   used by the system
`

func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, Usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return Serve(args[1:])
	case "setup-link":
		return setupLinkMain(args[1:])
	case "acme-auth":
		return hookMain(panelcfg.HookAuth)
	case "acme-cleanup":
		return hookMain(panelcfg.HookCleanup)
	case "help", "-h", "--help":
		fmt.Print(Usage)
		return 0
	}
	fmt.Fprint(os.Stderr, Usage)
	return 2
}
