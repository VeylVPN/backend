//go:build !windows

package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/veylvpn/backend/internal/config"
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

func (a *Agent) peerAllowed(c *net.UnixConn) bool {
	uid, err := peerUID(c)
	return err == nil && a.allowed(uid)
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
	group := a.Group
	if group == "" {
		group = config.ServiceUser
	}
	if _, gid, err := a.Lookup(group); err == nil {
		_ = a.Chown(sock, 0, gid)
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func leftovers() []string {
	return []string{config.BinPath, "/opt/veyl"}
}

func execInstaller(argv []string) error {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C.UTF-8", "HOME=/root"}
	return syscall.Exec(argv[0], argv, env)
}

func runnerEnv() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "HOME=/tmp", "DEBIAN_FRONTEND=noninteractive", "SYSTEMD_PAGER="}
}
