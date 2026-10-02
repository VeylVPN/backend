package agent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/veylvpn/backend/internal/winacl"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceEx = kernel32.NewProc("GetDiskFreeSpaceExW")
)

func diskUsage(path string) (uint64, uint64, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var avail, total, free uint64
	r, _, e := procGetDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if r == 0 {
		return 0, 0, e
	}
	return total, avail, nil
}

func (a *Agent) peerAllowed(c *net.UnixConn) bool {
	return true
}

func (a *Agent) Listen(sock string) (*net.UnixListener, error) {
	a.init()
	dir := filepath.Dir(sock)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	grants, err := RunDirGrants()
	if err != nil {
		return nil, err
	}
	if err := winacl.Protect(dir, true, grants); err != nil {
		return nil, fmt.Errorf("protect %s: %w", dir, err)
	}
	if fi, err := os.Lstat(sock); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", sock)
		}
		if err := os.Remove(sock); err != nil {
			return nil, err
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	return ln, nil
}

func leftovers() []string {
	return nil
}

func execInstaller(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runnerEnv() []string {
	return os.Environ()
}
