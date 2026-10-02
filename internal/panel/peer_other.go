//go:build !linux

package panel

import "net"

func peerIsRoot(c net.Conn) bool {
	return false
}
