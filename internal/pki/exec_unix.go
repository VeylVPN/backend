//go:build !windows

package pki

const defaultOpenVPNBin = "/usr/sbin/openvpn"

func openvpnEnv() ([]string, string) {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}, "/"
}
