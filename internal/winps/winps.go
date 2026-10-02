package winps

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var Flags = []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"}

var ErrScript = errors.New("unsafe powershell script")

const prelude = "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'"

const maxScript = 24 << 10

func isQuote(r rune) bool {
	switch r {
	case '\'', '‘', '’', '‚', '‛':
		return true
	}
	return false
}

func Quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for _, r := range s {
		if isQuote(r) {
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

type Arg interface {
	ps() string
}

type str string

func (s str) ps() string { return Quote(string(s)) }

type num int64

func (n num) ps() string { return strconv.FormatInt(int64(n), 10) }

type flag bool

func (f flag) ps() string {
	if f {
		return "$true"
	}
	return "$false"
}

func S(s string) Arg { return str(s) }
func I(n int) Arg    { return num(int64(n)) }
func B(b bool) Arg   { return flag(b) }

func List(items ...string) Arg {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = Quote(it)
	}
	return raw("@(" + strings.Join(q, ", ") + ")")
}

func Ints(items ...int) Arg {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = strconv.Itoa(it)
	}
	return raw("@(" + strings.Join(q, ", ") + ")")
}

type raw string

func (r raw) ps() string { return string(r) }

func Line(format string, args ...Arg) string {
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.ps()
	}
	return fmt.Sprintf(format, vals...)
}

type Script struct {
	lines []string
}

func (s *Script) Add(format string, args ...Arg) {
	s.lines = append(s.lines, Line(format, args...))
}

func (s *Script) String() string {
	return strings.Join(s.lines, "\n") + "\n"
}

func Command(script string) ([]string, error) {
	if script == "" || len(script) > maxScript || strings.ContainsAny(script, "\"\x00") {
		return nil, ErrScript
	}
	body := prelude + "\n" + strings.TrimSpace(strings.ReplaceAll(script, "\r\n", "\n"))
	return append(append([]string{}, Flags...), body), nil
}
