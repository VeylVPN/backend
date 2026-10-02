package hook

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/hookapi"
	"github.com/veylvpn/backend/internal/pki"
)

const (
	exitAllow = 0
	exitDeny  = 1
)

var errMetadata = errors.New("invalid metadata")

func instance() string {
	switch os.Getenv("dev") {
	case config.TunUDP:
		return config.InstanceUDP
	case config.TunTCP:
		return config.InstanceTCP
	}
	return ""
}

func readMetadata() (string, error) {
	if os.Getenv("metadata_type") != "0" {
		return "", errMetadata
	}
	path := os.Getenv("metadata_file")
	if path == "" || !filepath.IsAbs(path) {
		return "", errMetadata
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() < 1 || fi.Size() > pki.MaxMetadata {
		return "", errMetadata
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errMetadata
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, pki.MaxMetadata+1))
	if err != nil || len(b) < 1 || len(b) > pki.MaxMetadata {
		return "", errMetadata
	}
	id := string(b)
	if !ValidCN(id) {
		return "", errMetadata
	}
	return id, nil
}

func validPush(p string) bool {
	f := strings.Fields(p)
	if len(f) != 3 || f[0] != "dhcp-option" || f[1] != "DNS" || strings.Join(f, " ") != p {
		return false
	}
	_, ok := config.MaskForAddr(f[2])
	return ok
}

func writePush(path string, push []string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("bad output path")
	}
	var sb strings.Builder
	for _, p := range push {
		if !validPush(p) {
			return errors.New("refusing push option")
		}
		sb.WriteString("push \"" + p + "\"\n")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(sb.String()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func Main(args []string) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", config.DefaultPaths().HookSock(), "")
	timeout := fs.Duration("timeout", 5*time.Second, "")
	if err := fs.Parse(args); err != nil {
		return exitDeny
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return exitDeny
	}
	if *timeout <= 0 || *timeout > 30*time.Second {
		*timeout = 5 * time.Second
	}
	switch rest[0] {
	case hookapi.EventVerify:
		if len(rest) != 1 {
			return exitDeny
		}
		id, err := readMetadata()
		if err != nil {
			return exitDeny
		}
		resp, err := hookapi.Ask(*socket, hookapi.Request{Event: hookapi.EventVerify, CN: id, Instance: instance()}, *timeout)
		if err != nil || !resp.Allow {
			return exitDeny
		}
		return exitAllow
	case hookapi.EventConnect:
		if len(rest) != 2 {
			return exitDeny
		}
		cn := os.Getenv("common_name")
		if !ValidCN(cn) {
			return exitDeny
		}
		resp, err := hookapi.Ask(*socket, hookapi.Request{Event: hookapi.EventConnect, CN: cn, Instance: instance()}, *timeout)
		if err != nil || !resp.Allow {
			return exitDeny
		}
		if err := writePush(rest[1], resp.Push); err != nil {
			return exitDeny
		}
		return exitAllow
	case hookapi.EventDisconnect:
		return exitAllow
	}
	return exitDeny
}
