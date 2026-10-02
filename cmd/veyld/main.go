package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/veylvpn/backend/internal/api"
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
	data := flag.String("data", env("VEYL_DATA", "/var/lib/veyl"), "")
	listen := flag.String("listen", env("VEYL_LISTEN", "127.0.0.1:8080"), "")
	endpoint := flag.String("endpoint", env("VEYL_ENDPOINT", ""), "")
	static := flag.String("static", env("VEYL_STATIC", ""), "")
	mgmt := flag.String("mgmt", env("VEYL_MGMT", "/run/veyl/mgmt"), "")
	flag.Parse()

	args := flag.Args()
	if len(args) > 0 && args[0] == "init" {
		dir := *data
		if len(args) > 1 {
			dir = args[1]
		}
		if _, err := pki.Init(dir); err != nil {
			die("init failed")
		}
		return
	}

	st, err := store.Open(filepath.Join(*data, "state.json"))
	if err != nil {
		die("state unavailable")
	}
	ca, err := pki.Init(*data)
	if err != nil {
		die("pki unavailable")
	}
	crl := filepath.Join(*data, pki.CRLFile)
	m := &ovpn.Client{Socket: *mgmt}

	if len(args) > 0 {
		cli(st, ca, m, crl, args)
		return
	}

	if *endpoint == "" {
		die("endpoint required")
	}
	if serials, err := st.Revoked(); err == nil {
		_ = ca.WriteCRL(crl, serials)
	}
	cfg := api.Config{
		Endpoint:         *endpoint,
		Port:             1194,
		Proto:            "udp",
		StaticDir:        *static,
		CRLPath:          crl,
		OpenRegistration: os.Getenv("VEYL_OPEN_REGISTRATION") == "1",
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(cfg, st, ca, m).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if err := srv.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}

func cli(st *store.Store, ca *pki.CA, m *ovpn.Client, crl string, args []string) {
	if args[0] == "account" && len(args) > 1 {
		switch {
		case args[1] == "new":
			n, err := st.NewAccount()
			if err != nil {
				die("failed")
			}
			fmt.Println(n)
			return
		case args[1] == "delete" && len(args) > 2:
			devs, err := st.DeleteAccount(args[2])
			if err != nil {
				die(err.Error())
			}
			if serials, err := st.Revoked(); err == nil {
				_ = ca.WriteCRL(crl, serials)
			}
			for _, d := range devs {
				_ = m.Kill(d.ID)
			}
			fmt.Println("deleted")
			return
		}
	}
	fmt.Fprintln(os.Stderr, "usage: veyld [init [dir] | account new | account delete <number>]")
	os.Exit(2)
}
