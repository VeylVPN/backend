package pki

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

const (
	MaxMetadata     = 256
	maxKeyFile      = 8 << 10
	serverKeyHeader = "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
	clientKeyHeader = "-----BEGIN OpenVPN tls-crypt-v2 client key-----"
	KeyGroup        = "veyl"
)

var (
	OpenVPNBin     = defaultOpenVPNBin
	OpenVPNTimeout = 20 * time.Second
	ErrOpenVPN     = errors.New("openvpn key generation failed")
	ErrMetadata    = errors.New("invalid tls-crypt-v2 metadata")
)

func runOpenVPN(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), OpenVPNTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, OpenVPNBin, args...)
	cmd.Env, cmd.Dir = openvpnEnv()
	if err := cmd.Run(); err != nil {
		return errors.Join(ErrOpenVPN, err)
	}
	return nil
}

func genKey(header string, args func(out string) []string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "veyl-key-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	out := filepath.Join(dir, "key")
	if err := runOpenVPN(args(out)...); err != nil {
		return nil, err
	}
	f, err := os.Open(out)
	if err != nil {
		return nil, errors.Join(ErrOpenVPN, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, errors.Join(ErrOpenVPN, err)
	}
	if len(b) == 0 || len(b) > maxKeyFile || !bytes.HasPrefix(bytes.TrimSpace(b), []byte(header)) {
		return nil, ErrOpenVPN
	}
	return b, nil
}

func shareWithGroup(path string) {
	if os.Geteuid() != 0 {
		return
	}
	g, err := user.LookupGroup(KeyGroup)
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	_ = os.Chown(path, 0, gid)
}

func GenerateTLSCryptV2Server(path string) error {
	b, err := genKey(serverKeyHeader, func(out string) []string {
		return []string{"--genkey", "tls-crypt-v2-server", out}
	})
	if err != nil {
		return err
	}
	if err := writeFile(path, b, 0o640); err != nil {
		return err
	}
	shareWithGroup(path)
	return nil
}

func ValidMetadata(m []byte) bool {
	return len(m) >= 1 && len(m) <= MaxMetadata
}

func (c *CA) TLSCryptV2ServerPath() string {
	return filepath.Join(c.dir, TLSCryptV2File)
}

func (c *CA) TLSCryptV2Client(metadata []byte) ([]byte, error) {
	if !ValidMetadata(metadata) {
		return nil, ErrMetadata
	}
	srv := c.TLSCryptV2ServerPath()
	if !exists(srv) {
		return nil, ErrOpenVPN
	}
	md := base64.StdEncoding.EncodeToString(metadata)
	return genKey(clientKeyHeader, func(out string) []string {
		return []string{"--tls-crypt-v2", srv, "--genkey", "tls-crypt-v2-client", out, md}
	})
}
