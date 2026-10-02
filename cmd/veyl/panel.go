package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/agent"
	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/panel"
	"github.com/veylvpn/backend/internal/panelcfg"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/privdrop"
)

func asPanelUser() error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := privdrop.To(panelcfg.User); err != nil {
		return fmt.Errorf("cannot switch to the %s user: %w", panelcfg.User, err)
	}
	return nil
}

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("run this as root")
	}
	return nil
}

func panelMain(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, panel.Usage)
		return 2
	}
	rest := args[1:]
	switch args[0] {
	case "serve", "setup-link":
		if err := asPanelUser(); err != nil {
			return fail(err)
		}
		return panel.Main(args)
	case "agent":
		return panelAgentMain()
	case "install":
		return panelInstallMain(rest)
	case "uninstall":
		return panelUninstallMain(rest)
	case "pair":
		return panelPairMain(rest)
	case "acme-deploy":
		if err := needRoot(); err != nil {
			return fail(err)
		}
		if err := agent.NewPanel().DeployHook(context.Background(), os.Getenv("RENEWED_LINEAGE")); err != nil {
			return fail(err)
		}
		return 0
	case "update":
		return panelOp(agentapi.OpUpdate)
	case "status":
		return panelOp(agentapi.OpStatus)
	case "recover":
		return panelRecoverMain(rest)
	case "backup":
		return panelBackupMain(rest)
	case "restore":
		return panelRestoreMain(rest)
	}
	return panel.Main(args)
}

func panelAgentMain() int {
	if err := needRoot(); err != nil {
		return fail(err)
	}
	pa := agent.NewPanel()
	ln, err := pa.Listen(pa.Panel.AgentSock())
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := pa.Serve(ctx, ln); err != nil {
		return fail(err)
	}
	return 0
}

func emitter() func(agentapi.Event) {
	return func(ev agentapi.Event) {
		if ev.Step == "" {
			return
		}
		if ev.Detail != "" {
			fmt.Printf("    %-12s %-4s %s\n", ev.Step, ev.Status, ev.Detail)
		} else {
			fmt.Printf("    %-12s %s\n", ev.Step, ev.Status)
		}
	}
}

func panelInstallMain(args []string) int {
	fs := flag.NewFlagSet("panel install", flag.ContinueOnError)
	domain := fs.String("domain", "", "")
	email := fs.String("email", "", "")
	ip := fs.String("ip", "", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := needRoot(); err != nil {
		return fail(err)
	}
	pa := agent.NewPanel()
	pub := *ip
	if pub == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		pub, _ = pa.Probe.PublicIP(ctx, false)
		cancel()
	}
	fmt.Println("Installing Veyl Control")
	token, err := pa.Install(context.Background(), emitter(), agent.PanelInstallOpts{Domain: *domain, Email: *email, PublicIP: pub})
	if err != nil {
		return fail(err)
	}
	if token == "" {
		fmt.Println("\nVeyl Control is up to date and running.")
		return 0
	}
	host := pub
	if host == "" {
		host = "<server-ip>"
	}
	line := "=================================================================="
	fmt.Printf("\n\033[1;32m%s\033[0m\n\n", line)
	fmt.Printf("  \033[1mVeyl Control is installed.\033[0m\n\n")
	fmt.Printf("  Open this link to finish setup:\n\n")
	fmt.Printf("    \033[1m%s\033[0m\n\n", panel.SetupLink(host, token, false))
	fmt.Printf("  Port 80 blocked? Use https://%s%s/setup#%s and accept the\n  self-signed warning once.\n", host, panelcfg.SetupPrefix, token)
	fmt.Printf("  Lost the link? Run: sudo veyl panel setup-link\n")
	fmt.Printf("\n\033[1;32m%s\033[0m\n\n", line)
	return 0
}

func panelUninstallMain(args []string) int {
	fs := flag.NewFlagSet("panel uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := needRoot(); err != nil {
		return fail(err)
	}
	if err := agent.NewPanel().Uninstall(context.Background(), emitter(), *purge); err != nil {
		return fail(err)
	}
	fmt.Println("Veyl Control was removed.")
	return 0
}

func panelPairMain(args []string) int {
	fs := flag.NewFlagSet("panel pair", flag.ContinueOnError)
	scope := fs.String("scope", panelkey.ScopeManage, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := asService(); err != nil {
		return fail(err)
	}
	d, err := loadDeps()
	if err != nil {
		return fail(err)
	}
	u, err := panelkey.NodeURL(d.Settings.Get().Host)
	if err != nil {
		return fail(errors.New("finish the node setup first, it needs a server address"))
	}
	code, exp, err := admin.New(d).NewPairingCode(u, *scope)
	if err != nil {
		return fail(err)
	}
	fmt.Println("Pairing code for Veyl Control (works once, until " + exp.Local().Format("15:04") + "):")
	fmt.Println()
	fmt.Println("  " + code)
	fmt.Println()
	return 0
}

func panelOp(op string) int {
	var data map[string]string
	err := agentapi.SocketClient{Path: panel.Paths().AgentSock()}.Do(context.Background(), agentapi.Request{Op: op}, func(ev agentapi.Event) {
		emitter()(ev)
		if ev.Done {
			data = ev.Data
		}
	})
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s=%s\n", k, data[k])
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

func systemctl(args ...string) {
	pa := agent.NewPanel()
	_, _ = pa.Runner.Run(context.Background(), "systemctl", args...)
}

func chownPanel(paths []string) {
	u, err := user.Lookup(panelcfg.User)
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, p := range paths {
		_ = os.Lchown(p, uid, gid)
	}
}

func panelRecoverMain(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, panel.Usage)
		return 2
	}
	if err := needRoot(); err != nil {
		return fail(err)
	}
	paths := panel.Paths()
	systemctl("stop", panelcfg.UnitPanel)
	pw, err := panel.RecoverUser(paths, args[0])
	chownPanel([]string{paths.DB()})
	systemctl("start", panelcfg.UnitPanel)
	if err != nil {
		if users, lerr := panel.ListUsers(paths); lerr == nil && len(users) > 0 {
			fmt.Fprintln(os.Stderr, "Panel users:")
			for _, u := range users {
				fmt.Fprintln(os.Stderr, "  "+u)
			}
		}
		return fail(err)
	}
	fmt.Printf("New password for %s: %s\n", args[0], pw)
	fmt.Println("Two-step sign in was reset. It is set up again right after the next sign in.")
	return 0
}

func panelBackupMain(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, panel.Usage)
		return 2
	}
	pass, err := readPassphrase()
	if err != nil {
		return fail(err)
	}
	data, err := panel.CreateBackup(panel.Paths(), nil, pass)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(args[0], data, 0o600); err != nil {
		return fail(err)
	}
	fmt.Println("Encrypted panel backup written to", args[0])
	return 0
}

func panelRestoreMain(args []string) int {
	fs := flag.NewFlagSet("panel restore", flag.ContinueOnError)
	force := fs.Bool("force", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, panel.Usage)
		return 2
	}
	if err := needRoot(); err != nil {
		return fail(err)
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fail(err)
	}
	pass, err := readPassphrase()
	if err != nil {
		return fail(err)
	}
	systemctl("stop", panelcfg.UnitPanel)
	written, err := panel.RestoreBackup(panel.Paths(), data, pass, *force)
	chownPanel(written)
	if err == nil {
		systemctl("start", panelcfg.UnitPanel)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, _ = agent.NewPanel().Do(ctx, panelcfg.OpSite, "", nil)
	}
	if err != nil {
		return fail(err)
	}
	fmt.Println("Restored. Veyl Control restarted with the backup.")
	return 0
}
