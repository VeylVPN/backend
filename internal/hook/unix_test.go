package hook

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func requireUnixSockets(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	dir, err := os.MkdirTemp("", "vu")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	l, err := net.Listen("unix", filepath.Join(dir, "probe"))
	if err != nil {
		t.Skip("AF_UNIX sockets are not available here:", err)
	}
	l.Close()
}
