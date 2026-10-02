package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/privdrop"
	"github.com/veylvpn/backend/internal/store"
)

func paths() config.Paths {
	p := config.DefaultPaths()
	if v := os.Getenv("VEYL_DATA"); v != "" {
		p.Data = v
	}
	if v := os.Getenv("VEYL_RUN"); v != "" {
		p.Run = v
	}
	return p
}

func loadDeps() (app.Deps, error) {
	p := paths()
	live, err := config.NewLive(p.Settings())
	if err != nil {
		return app.Deps{}, fmt.Errorf("settings: %w", err)
	}
	st, err := store.Open(p.State())
	if err != nil {
		return app.Deps{}, fmt.Errorf("state: %w", err)
	}
	ca, err := pki.Init(p.PKI())
	if err != nil {
		return app.Deps{}, fmt.Errorf("pki: %w", err)
	}
	st.SetDefaultLimit(live.Get().DeviceLimit)
	return app.Deps{
		Paths:    p,
		Settings: live,
		Store:    st,
		CA:       ca,
		Mgmt:     &ovpn.Multi{Clients: mgmtClients(p)},
		Agent:    agentapi.SocketClient{Path: p.AgentSock()},
	}, nil
}

func mgmtClients(p config.Paths) []*ovpn.Client {
	if config.Platform == config.PlatformWindows {
		out := []*ovpn.Client{}
		for _, in := range []string{config.InstanceUDP, config.InstanceTCP} {
			out = append(out, &ovpn.Client{Socket: fmt.Sprintf("%s%s:%d", ovpn.TCPPrefix, config.MgmtHost, config.MgmtPort(in)), PasswordFile: p.MgmtPassword(in)})
		}
		return out
	}
	return []*ovpn.Client{{Socket: p.Mgmt(config.InstanceUDP)}, {Socket: p.Mgmt(config.InstanceTCP)}}
}

func asService() error {
	if !privdrop.Elevated() || config.Platform == config.PlatformWindows {
		return nil
	}
	if err := privdrop.To(config.ServiceUser); err != nil {
		if errors.Is(err, privdrop.ErrNotRoot) {
			return err
		}
		return fmt.Errorf("cannot switch to the %s user: %w", config.ServiceUser, err)
	}
	return nil
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "veyl:", err)
	return 1
}

func initMain(args []string) int {
	dir := paths().PKI()
	if len(args) > 0 {
		dir = args[0]
	}
	if _, err := pki.Init(dir); err != nil {
		return fail(err)
	}
	return 0
}
