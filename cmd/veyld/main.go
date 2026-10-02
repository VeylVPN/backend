package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/veylvpn/backend/internal/api"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/hook"
	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func main() {
	log.SetOutput(io.Discard)
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		os.Exit(hook.Main(os.Args[2:]))
	}
	data := flag.String("data", env("VEYL_DATA", config.DataDir), "")
	run := flag.String("run", env("VEYL_RUN", config.RunDir), "")
	listen := flag.String("listen", env("VEYL_LISTEN", config.WebListen), "")
	flag.Parse()
	paths := config.Paths{Data: *data, Run: *run}

	args := flag.Args()
	if len(args) > 0 && args[0] == "init" {
		if _, err := pki.Init(paths.PKI()); err != nil {
			die("init failed")
		}
		return
	}

	st, err := store.Open(paths.State())
	if err != nil {
		die("state unavailable")
	}
	ca, err := pki.Init(paths.PKI())
	if err != nil {
		die("pki unavailable")
	}
	live, err := config.NewLive(paths.Settings())
	if err != nil {
		die("settings unavailable")
	}
	mgmt := &ovpn.Multi{Clients: []*ovpn.Client{
		{Socket: paths.Mgmt(config.InstanceUDP)},
		{Socket: paths.Mgmt(config.InstanceTCP)},
	}}
	d := app.Deps{Paths: paths, Settings: live, Store: st, CA: ca, Mgmt: mgmt}

	if len(args) > 0 {
		cli(d, args)
		return
	}

	if serials, err := st.Revoked(); err == nil {
		_ = ca.WriteCRL(paths.CRL(), serials)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := hook.NewServer(d).Serve(ctx, paths.HookSock()); err != nil {
			fmt.Fprintln(os.Stderr, "hook socket unavailable")
		}
	}()
	srv := api.HTTPServer(*listen, api.New(d).Handler())
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
		os.Exit(1)
	}
}

func cli(d app.Deps, args []string) {
	if args[0] == "account" && len(args) > 1 {
		switch {
		case args[1] == "new":
			n, err := d.Store.NewAccount()
			if err != nil {
				die("failed")
			}
			fmt.Println(n)
			return
		case args[1] == "delete" && len(args) > 2:
			devs, err := d.Store.DeleteAccount(args[2])
			if err != nil {
				die(err.Error())
			}
			_ = api.RevokeEffects(d, devs)
			fmt.Println("deleted")
			return
		}
	}
	fmt.Fprintln(os.Stderr, "usage: veyld [init | account new | account delete <number> | hook verify|connect|disconnect]")
	os.Exit(2)
}
