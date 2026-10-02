//go:build !windows

package hook

import "os"

func (s *Server) secure(path string) error {
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	return s.chgrp(path)
}
