package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/veylvpn/backend/internal/agent"
	"github.com/veylvpn/backend/internal/app"
	"github.com/veylvpn/backend/internal/dns"
	"github.com/veylvpn/backend/internal/hook"
)

const usage = `usage: veyl <command>

  status                      show service health
  setup-link                  print a fresh setup link
  account new [-label L] [-expires-days N] [-password]
  account list
  account delete <number|id>
  invite new [-uses N] [-days N]
  admin reset-password        set a new random admin password
  backup <file>               write an encrypted backup
  restore [-force] <file>     restore an encrypted backup
  update [-branch B]          update to the latest version
  uninstall [-purge]          remove Veyl from this server
  version

  serve | agent | dns | hook | init [dir]   used by the system services
`

func main() {
	log.SetOutput(io.Discard)
	agent.DownloadBlocklists = dns.Download
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	rest := args[1:]
	switch args[0] {
	case "serve":
		return serveMain(rest)
	case "agent":
		return agent.Main(rest)
	case "dns":
		return dns.Main(rest)
	case "hook":
		return hook.Main(rest)
	case "init":
		return initMain(rest)
	case "status":
		return agent.Main([]string{"run", "status"})
	case "update":
		return agent.Main(append([]string{"update"}, rest...))
	case "uninstall":
		return agent.Main(append([]string{"uninstall"}, rest...))
	case "account":
		return accountMain(rest)
	case "invite":
		return inviteMain(rest)
	case "admin":
		return adminMain(rest)
	case "setup-link":
		return setupLinkMain(rest)
	case "backup":
		return backupMain(rest)
	case "restore":
		return restoreMain(rest)
	case "version", "-v", "--version":
		fmt.Println("veyl", app.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Print(usage)
		return 0
	}
	fmt.Fprint(os.Stderr, usage)
	return 2
}
