package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/api"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/hook"
	"github.com/veylvpn/backend/internal/setup"
	"github.com/veylvpn/backend/internal/winsvc"
)

const vpnAdminPort = "8081"

func serveMain(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", config.WebListen, "")
	static := fs.String("static", "", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	d, err := loadDeps()
	if err != nil {
		return fail(err)
	}
	if serials, err := d.Store.Revoked(); err == nil {
		_ = d.CA.WriteCRL(d.Paths.CRL(), serials)
	}
	ctx, stop := signal.NotifyContext(winsvc.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hs := hook.NewServer(d)
	go func() { _ = hs.Serve(ctx, d.Paths.HookSock()) }()

	adminH := admin.New(d).Handler()
	h := routes(d, api.New(d).Handler(), adminH, setup.New(d).Handler(), *static)
	srv := api.HTTPServer(*listen, h)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	go vpnAdmin(ctx, d, adminH)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fail(err)
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	return 0
}

func routes(d app.Deps, apiH, adminH, setupH http.Handler, static string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/admin/", adminH)
	mux.Handle("/admin", adminH)
	mux.Handle("/admin/", adminH)
	mux.Handle("/v1/setup/", setupH)
	mux.Handle("/setup", setupH)
	mux.Handle("/setup/", setupH)
	mux.Handle("/v1/", apiH)
	var files http.Handler
	if static != "" {
		files = http.FileServer(http.Dir(static))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if files != nil && d.Settings.Get().Configured {
			files.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !d.Settings.Get().Configured {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	return mux
}

func vpnAdmin(ctx context.Context, d app.Deps, h http.Handler) {
	gateways := []string{config.UDPGW4, config.TCPGW4}
	running := map[string]*http.Server{}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		want := d.Settings.Get().AdminVPNOnly
		for _, gw := range gateways {
			srv := running[gw]
			if want && srv == nil {
				ln, err := net.Listen("tcp", net.JoinHostPort(gw, vpnAdminPort))
				if err != nil {
					continue
				}
				s := api.HTTPServer(ln.Addr().String(), h)
				running[gw] = s
				go func() { _ = s.Serve(ln) }()
			}
			if !want && srv != nil {
				_ = srv.Close()
				delete(running, gw)
			}
		}
		select {
		case <-ctx.Done():
			for _, s := range running {
				_ = s.Close()
			}
			return
		case <-tick.C:
		}
	}
}
