//go:build !windows

package privdrop

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func lookup(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func To(name string) error {
	uid, gid, err := lookup(name)
	if err != nil {
		return err
	}
	if os.Geteuid() == uid {
		return nil
	}
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		return errors.New("privilege drop failed")
	}
	return nil
}

func Elevated() bool {
	return os.Geteuid() == 0
}

func RequireRoot() error {
	if !Elevated() {
		return ErrNotRoot
	}
	return nil
}
