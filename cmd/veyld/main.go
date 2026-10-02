package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/veylvpn/backend/internal/api"
	"github.com/veylvpn/backend/internal/store"
	"github.com/veylvpn/backend/internal/wg"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	log.SetOutput(io.Discard)
	data := flag.String("data", env("VEYL_DATA", "/var/lib/veyl/state.json"), "")
	iface := flag.String("iface", env("VEYL_IFACE", "wg0"), "")
	listen := flag.String("listen", env("VEYL_LISTEN", "127.0.0.1:8080"), "")
	endpoint := flag.String("endpoint", env("VEYL_ENDPOINT", ""), "")
	static := flag.String("static", env("VEYL_STATIC", ""), "")
	origin := flag.String("origin", env("VEYL_ORIGIN", ""), "")
	flag.Parse()

	st, err := store.Open(*data, 5, 250)
	if err != nil {
		fmt.Fprintln(os.Stderr, "state:", err)
		os.Exit(1)
	}
	m := wg.Manager{Iface: *iface, Prefix: "10.66.0", Prefix6: "fd66:66:66::"}

	args := flag.Args()
	if len(args) > 0 {
		cli(st, m, args)
		return
	}

	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "endpoint required")
		os.Exit(1)
	}
	pub, err := m.ServerPublicKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wireguard interface unavailable")
		os.Exit(1)
	}
	for _, d := range st.All() {
		_ = m.AddPeer(d.PublicKey, d.Index)
	}
	cfg := api.Config{
		Endpoint:  *endpoint,
		DNS4:      "10.66.0.1",
		DNS6:      "fd66:66:66::1",
		StaticDir: *static,
		Origin:    *origin,
	}
	stop := make(chan struct{})
	go api.Scrubber(m, st, time.Minute, 10*time.Minute, stop)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(cfg, st, m, pub).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if err := srv.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}

func cli(st *store.Store, m wg.Manager, args []string) {
	switch args[0] {
	case "account":
		if len(args) > 1 && args[1] == "new" {
			n, err := st.NewAccount()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(n)
			return
		}
		if len(args) > 2 && args[1] == "delete" {
			devs, err := st.DeleteAccount(args[2])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for _, d := range devs {
				_ = m.RemovePeer(d.PublicKey)
			}
			fmt.Println("deleted")
			return
		}
	}
	fmt.Fprintln(os.Stderr, "usage: veyld [account new | account delete <number>]")
	os.Exit(2)
}
