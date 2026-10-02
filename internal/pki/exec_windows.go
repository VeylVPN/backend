package pki

import (
	"os"

	"github.com/veylvpn/backend/internal/config"
)

const defaultOpenVPNBin = config.WinOpenVPNBin

func openvpnEnv() ([]string, string) {
	return os.Environ(), ""
}
