package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"time"
)

type File struct {
	Name     string
	Perm     os.FileMode
	Required bool
}

func findFile(set []File, name string) (File, bool) {
	for _, f := range set {
		if f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

func CreateBundle(set []File, content map[string][]byte, passphrase string) ([]byte, error) {
	if err := checkPass(passphrase); err != nil {
		return nil, err
	}
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, f := range set {
		b, ok := content[f.Name]
		if !ok {
			if f.Required {
				return nil, ErrIncomplete
			}
			continue
		}
		if len(b) > maxFile {
			return nil, errors.New("file too large to back up")
		}
		hdr := &tar.Header{Name: f.Name, Mode: int64(f.Perm), Size: int64(len(b)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	k, err := key(passphrase, salt)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 0, len(Magic)+saltLen+nonceLen)
	head = append(head, Magic...)
	head = append(head, salt...)
	head = append(head, nonce...)
	out := aead.Seal(head, nonce, raw.Bytes(), head[:len(Magic)+saltLen])
	if len(out) > MaxSize {
		return nil, errors.New("backup too large")
	}
	return out, nil
}

func OpenBundle(set []File, data []byte, passphrase string) (map[string][]byte, error) {
	if len(data) > MaxSize || len(data) < len(Magic)+saltLen+nonceLen+16 || string(data[:len(Magic)]) != Magic {
		return nil, ErrFormat
	}
	if len(passphrase) == 0 || len(passphrase) > MaxPass*4 {
		return nil, ErrPassphrase
	}
	salt := data[len(Magic) : len(Magic)+saltLen]
	nonce := data[len(Magic)+saltLen : len(Magic)+saltLen+nonceLen]
	k, err := key(passphrase, salt)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, data[len(Magic)+saltLen+nonceLen:], data[:len(Magic)+saltLen])
	if err != nil {
		return nil, ErrPassphrase
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, ErrFormat
	}
	tr := tar.NewReader(io.LimitReader(gz, 4*maxFile))
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || hdr.Typeflag != tar.TypeReg || hdr.Size < 0 || hdr.Size > maxFile {
			return nil, ErrFormat
		}
		if _, ok := findFile(set, hdr.Name); !ok {
			return nil, ErrFormat
		}
		if _, dup := out[hdr.Name]; dup {
			return nil, ErrFormat
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		if err != nil || int64(len(b)) != hdr.Size {
			return nil, ErrFormat
		}
		out[hdr.Name] = b
	}
	for _, f := range set {
		if _, ok := out[f.Name]; f.Required && !ok {
			return nil, ErrIncomplete
		}
	}
	return out, nil
}
