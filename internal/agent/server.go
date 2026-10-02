package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
)

const (
	maxRequest = 4096
	opTimeout  = 30 * time.Minute
)

func diskUsage(path string) (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return cred.Uid, nil
}

func (a *Agent) Listen(sock string) (*net.UnixListener, error) {
	a.init()
	if err := os.MkdirAll(filepath.Dir(sock), 0o770); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", sock)
		}
		if err := os.Remove(sock); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	if _, gid, err := a.Lookup(config.ServiceUser); err == nil {
		_ = a.Chown(sock, 0, gid)
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (a *Agent) Serve(ctx context.Context, ln *net.UnixListener) error {
	a.init()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go a.handle(ctx, c)
	}
}

func (a *Agent) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	enc := json.NewEncoder(c)
	send := func(ev agentapi.Event) {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_ = enc.Encode(ev)
	}
	uid, err := peerUID(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, rerr := bufio.NewReaderSize(io.LimitReader(c, maxRequest), maxRequest).ReadSlice('\n')
	if err != nil || !a.allowed(uid) {
		send(agentapi.Event{Done: true, Error: "forbidden"})
		return
	}
	err = rerr
	if err != nil {
		send(agentapi.Event{Done: true, Error: "bad request"})
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var req agentapi.Request
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || len(req.Op) > 32 {
		send(agentapi.Event{Done: true, Error: "bad request"})
		return
	}
	opCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	data, err := a.Do(opCtx, req.Op, send)
	if err != nil {
		send(agentapi.Event{Done: true, Error: err.Error(), Data: data})
		return
	}
	send(agentapi.Event{Done: true, Data: data})
}

func Main(args []string) int {
	if len(args) == 0 {
		return serveMain(nil)
	}
	switch args[0] {
	case "serve":
		return serveMain(args[1:])
	case "run":
		return runMain(args[1:])
	case "bootstrap":
		return bootstrapMain(args[1:])
	case "uninstall":
		return uninstallMain(args[1:])
	case "update":
		return updateMain(args[1:])
	}
	fmt.Fprintln(os.Stderr, "usage: veyl agent [serve | run <op> | bootstrap [-domain d] [-email e] | uninstall [-purge] | update [-branch b]]")
	return 2
}

func needRoot() bool {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "this command must run as root")
		return false
	}
	return true
}

func serveMain(args []string) int {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	sock := fs.String("socket", config.DefaultPaths().AgentSock(), "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !needRoot() {
		return 1
	}
	a := New()
	ln, err := a.Listen(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Serve(ctx, ln); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		return 1
	}
	return 0
}

func printer(w io.Writer) Emit {
	return func(ev agentapi.Event) {
		if ev.Step == "" {
			return
		}
		if ev.Detail != "" {
			fmt.Fprintf(w, "%-14s %-4s %s\n", ev.Step, ev.Status, ev.Detail)
		} else {
			fmt.Fprintf(w, "%-14s %s\n", ev.Step, ev.Status)
		}
	}
}

func runMain(args []string) int {
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	sock := fs.String("socket", config.DefaultPaths().AgentSock(), "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: veyl agent run <apply|tls|status|dns-update|restart|ping>")
		return 2
	}
	pr := printer(os.Stdout)
	var data map[string]string
	err := agentapi.SocketClient{Path: *sock}.Do(context.Background(), agentapi.Request{Op: fs.Arg(0)}, func(ev agentapi.Event) {
		pr(ev)
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
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func bootstrapMain(args []string) int {
	fs := flag.NewFlagSet("agent bootstrap", flag.ContinueOnError)
	domain := fs.String("domain", "", "")
	email := fs.String("email", "", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !needRoot() {
		return 1
	}
	if err := New().Bootstrap(context.Background(), printer(os.Stdout), *domain, *email); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func uninstallMain(args []string) int {
	fs := flag.NewFlagSet("agent uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !needRoot() {
		return 1
	}
	a := New()
	err := a.Uninstall(context.Background(), printer(os.Stdout), *purge)
	for _, p := range []string{config.BinPath, "/opt/veyl"} {
		_ = os.RemoveAll(a.path(p))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

const (
	SourceDir   = "/opt/veyl/src"
	InstallPath = SourceDir + "/install.sh"
)

func UpdateArgs(branch string) ([]string, error) {
	argv := []string{"/bin/bash", InstallPath, "--yes"}
	if branch != "" {
		for _, r := range branch {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '/') {
				return nil, errors.New("invalid branch name")
			}
		}
		if len(branch) > 100 || strings.HasPrefix(branch, "-") {
			return nil, errors.New("invalid branch name")
		}
		argv = append(argv, "--branch", branch)
	}
	return argv, nil
}

func updateMain(args []string) int {
	fs := flag.NewFlagSet("agent update", flag.ContinueOnError)
	branch := fs.String("branch", "", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !needRoot() {
		return 1
	}
	argv, err := UpdateArgs(*branch)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if _, err := os.Stat(InstallPath); err != nil {
		fmt.Fprintln(os.Stderr, "installer not found at", InstallPath)
		return 1
	}
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C.UTF-8", "HOME=/root"}
	if err := syscall.Exec(argv[0], argv, env); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
