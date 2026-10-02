package winacl

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	SIDSystem = "S-1-5-18"
	SIDAdmins = "S-1-5-32-544"
)

const (
	Full   = "F"
	Modify = "M"
	Read   = "RX"
)

var ErrName = errors.New("invalid service name")

func validService(name string) bool {
	if name == "" || len(name) > 80 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func ServiceSID(name string) (string, error) {
	if !validService(name) {
		return "", ErrName
	}
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := sha1.Sum(b)
	parts := []string{"S-1-5-80"}
	for i := 0; i < 5; i++ {
		parts = append(parts, strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[4*i:])), 10))
	}
	return strings.Join(parts, "-"), nil
}

func ServiceAccount(name string) (string, error) {
	if !validService(name) {
		return "", ErrName
	}
	return `NT SERVICE\` + name, nil
}

type Grant struct {
	SID    string
	Rights string
}

func validSID(s string) bool {
	if !strings.HasPrefix(s, "S-1-") || len(s) > 184 {
		return false
	}
	for _, p := range strings.Split(s[4:], "-") {
		if p == "" || len(p) > 10 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validRights(r string) bool {
	return r == Full || r == Modify || r == Read
}

func IcaclsArgs(path string, dir bool, grants []Grant) ([]string, error) {
	if path == "" || strings.ContainsAny(path, "\"\r\n*?<>|") || len(grants) == 0 {
		return nil, errors.New("invalid acl request")
	}
	args := []string{path, "/inheritance:r"}
	for _, g := range grants {
		if !validSID(g.SID) || !validRights(g.Rights) {
			return nil, errors.New("invalid acl grant")
		}
		inherit := ""
		if dir {
			inherit = "(OI)(CI)"
		}
		args = append(args, "/grant:r", "*"+g.SID+":"+inherit+"("+g.Rights+")")
	}
	args = append(args, "/C", "/Q")
	return args, nil
}

func sddlRights(r string) string {
	switch r {
	case Full:
		return "FA"
	case Modify:
		return "0x1301bf"
	}
	return "0x1200a9"
}

func SDDL(dir bool, grants []Grant) (string, error) {
	var b strings.Builder
	b.WriteString("D:PAI")
	for _, g := range grants {
		if !validSID(g.SID) || !validRights(g.Rights) {
			return "", errors.New("invalid acl grant")
		}
		flags := ""
		if dir {
			flags = "OICI"
		}
		b.WriteString("(A;" + flags + ";" + sddlRights(g.Rights) + ";;;" + g.SID + ")")
	}
	return b.String(), nil
}
