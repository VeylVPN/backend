//go:build !windows

package winacl

import "errors"

func Protect(path string, dir bool, grants []Grant) error {
	return errors.New("access control lists are only set on Windows")
}
