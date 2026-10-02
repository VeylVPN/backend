package web

import (
	"errors"
	"io/fs"
)

var BrandFiles = []string{"brand.css", "brand.js", "mark.svg", "mark-white.svg", "wordmark.svg", "favicon.svg"}

type brandFS struct{ base fs.FS }

func (b brandFS) Open(name string) (fs.File, error) {
	if name == "." {
		return b.base.Open(name)
	}
	for _, f := range BrandFiles {
		if f == name {
			return b.base.Open(name)
		}
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (b brandFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	all, err := fs.ReadDir(b.base, ".")
	if err != nil {
		return nil, err
	}
	var out []fs.DirEntry
	for _, e := range all {
		for _, f := range BrandFiles {
			if e.Name() == f {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func Brand() fs.FS {
	return brandFS{base: Assets()}
}

type overlay []fs.FS

func (o overlay) Open(name string) (fs.File, error) {
	if name == "." {
		return o[0].Open(name)
	}
	var last error = fs.ErrNotExist
	for _, f := range o {
		file, err := f.Open(name)
		if err == nil {
			return file, nil
		}
		last = err
	}
	if errors.Is(last, fs.ErrNotExist) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return nil, last
}

func (o overlay) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	seen := map[string]bool{}
	var out []fs.DirEntry
	for _, f := range o {
		es, err := fs.ReadDir(f, ".")
		if err != nil {
			continue
		}
		for _, e := range es {
			if !seen[e.Name()] {
				seen[e.Name()] = true
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func Overlay(layers ...fs.FS) fs.FS {
	return overlay(layers)
}
