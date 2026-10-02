package dns

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"strings"
)

const maxLineLen = 4096

func ParseLine(line string) []string {
	var out []string
	parseLine(line, func(d string) { out = append(out, d) })
	return out
}

func Parse(r io.Reader, emit func(string)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	skipping := false
	for {
		chunk, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			skipping = true
			continue
		}
		if len(chunk) > 0 && !skipping && len(chunk) <= maxLineLen {
			parseLine(string(chunk), emit)
		}
		skipping = false
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func parseLine(line string, emit func(string)) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '!' || line[0] == '[' || strings.HasPrefix(line, "@@") {
		return
	}
	f := strings.Fields(line)
	if len(f) == 1 {
		if d, ok := normalizeToken(f[0]); ok {
			emit(d)
		}
		return
	}
	a, err := netip.ParseAddr(f[0])
	if err != nil || !(a.IsUnspecified() || a.IsLoopback()) {
		return
	}
	for _, t := range f[1:] {
		if d, ok := Normalize(t); ok {
			emit(d)
		}
	}
}

func normalizeToken(t string) (string, bool) {
	if strings.HasPrefix(t, "||") {
		t = t[2:]
		if i := strings.IndexByte(t, '$'); i >= 0 {
			if opt := t[i+1:]; opt != "" && opt != "important" {
				return "", false
			}
			t = t[:i]
		}
		if !strings.HasSuffix(t, "^") {
			return "", false
		}
		t = t[:len(t)-1]
	} else if strings.HasPrefix(t, "*.") {
		t = t[2:]
	} else if strings.HasPrefix(t, ".") {
		t = t[1:]
	}
	return Normalize(t)
}

func Normalize(s string) (string, bool) {
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	var b []byte
	labels, start := 0, 0
	digitsOnly := true
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			n := i - start
			if n == 0 || n > 63 {
				return "", false
			}
			labels++
			if i < len(s) {
				digitsOnly = true
				start = i + 1
			}
			continue
		}
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c == '-', c == '_':
			digitsOnly = false
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
			digitsOnly = false
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + 'a' - 'A'
		default:
			return "", false
		}
	}
	if labels < 2 || digitsOnly {
		return "", false
	}
	if b != nil {
		s = string(b)
	}
	if s == "localhost.localdomain" || strings.HasSuffix(s, ".localhost") {
		return "", false
	}
	return s, true
}
