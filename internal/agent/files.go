package agent

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const prevSuffix = ".veyl-prev"

type saved struct {
	path    string
	existed bool
}

type txn struct {
	a       *Agent
	changes []saved
}

func (a *Agent) txn() *txn {
	return &txn{a: a}
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".veyl-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (t *txn) put(path, data string, mode os.FileMode) (bool, error) {
	full := t.a.path(path)
	old, err := os.ReadFile(full)
	existed := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if existed && bytes.Equal(old, []byte(data)) {
		if fi, err := os.Stat(full); err == nil && fi.Mode().Perm() != mode {
			if err := os.Chmod(full, mode); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	if existed {
		fi, err := os.Stat(full)
		if err != nil {
			return false, err
		}
		if err := writeAtomic(full+prevSuffix, old, fi.Mode().Perm()); err != nil {
			return false, err
		}
	}
	if err := writeAtomic(full, []byte(data), mode); err != nil {
		return false, err
	}
	t.changes = append(t.changes, saved{path: full, existed: existed})
	return true, nil
}

func (t *txn) rollback() error {
	var errs []error
	for i := len(t.changes) - 1; i >= 0; i-- {
		c := t.changes[i]
		if c.existed {
			errs = append(errs, os.Rename(c.path+prevSuffix, c.path))
		} else {
			if err := os.Remove(c.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	t.changes = nil
	return errors.Join(errs...)
}

func (t *txn) changed() bool {
	return len(t.changes) > 0
}

func (a *Agent) remove(path string) (bool, error) {
	err := os.Remove(a.path(path))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (a *Agent) exists(path string) bool {
	_, err := os.Lstat(a.path(path))
	return err == nil
}

func (a *Agent) ensureDir(path string, mode os.FileMode, uid, gid int) error {
	full := a.path(path)
	if err := os.MkdirAll(full, mode.Perm()); err != nil {
		return err
	}
	if err := os.Chmod(full, mode); err != nil {
		return err
	}
	if uid >= 0 {
		return a.Chown(full, uid, gid)
	}
	return nil
}

func (a *Agent) setPerm(path string, mode os.FileMode, uid, gid int) error {
	full := a.path(path)
	if err := a.Chown(full, uid, gid); err != nil {
		return err
	}
	return os.Chmod(full, mode)
}
