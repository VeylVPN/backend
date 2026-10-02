package dns

import (
	"hash/fnv"
	"reflect"
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"example.com", []string{"example.com"}},
		{"Example.COM.", []string{"example.com"}},
		{"  ads.example.com  \r", []string{"ads.example.com"}},
		{"ads.example.com # inline", []string{"ads.example.com"}},
		{"ads.example.com#x", []string{"ads.example.com"}},
		{"# comment", nil},
		{"! adblock comment", nil},
		{"[Adblock Plus 2.0]", nil},
		{"", nil},
		{"0.0.0.0 track.example.org", []string{"track.example.org"}},
		{"127.0.0.1\tmal.example.net", []string{"mal.example.net"}},
		{":: v6.example.net", []string{"v6.example.net"}},
		{"::1 v6b.example.net", []string{"v6b.example.net"}},
		{"0.0.0.0 a.example.com b.example.com # two", []string{"a.example.com", "b.example.com"}},
		{"1.2.3.4 redirect.example.com", nil},
		{"0.0.0.0 0.0.0.0", nil},
		{"127.0.0.1 localhost", nil},
		{"127.0.0.1 localhost.localdomain", nil},
		{"::1 ip6-localhost ip6-loopback", nil},
		{"0.0.0.0 broadcasthost", nil},
		{"*.wild.example.com", []string{"wild.example.com"}},
		{".dot.example.com", []string{"dot.example.com"}},
		{"||abp.example.com^", []string{"abp.example.com"}},
		{"||abp.example.com^$important", []string{"abp.example.com"}},
		{"||abp.example.com^$third-party", nil},
		{"||abp.example.com", nil},
		{"@@||allowed.example.com^", nil},
		{"/regex/", nil},
		{"1.2.3.4", nil},
		{"2001:db8::1", nil},
		{"com", nil},
		{"localhost", nil},
		{"under_score.example.com", []string{"under_score.example.com"}},
		{"xn--bcher-kva.example", []string{"xn--bcher-kva.example"}},
		{"bücher.example", nil},
		{"bad..example.com", nil},
		{"space in.example.com x", nil},
		{"http://example.com/path", nil},
		{"example.123", nil},
		{"123.example.com", []string{"123.example.com"}},
		{strings.Repeat("a", 64) + ".com", nil},
		{strings.Repeat("a", 63) + ".com", []string{strings.Repeat("a", 63) + ".com"}},
		{strings.Repeat("abcdefghi.", 26) + "com", nil},
	}
	for _, c := range cases {
		got := ParseLine(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseReader(t *testing.T) {
	in := "# header\r\nA.example.com\r\n" + strings.Repeat("x", 70000) + ".example.com\n" +
		"0.0.0.0 b.example.com\r\n\r\n||c.example.com^\nlast.example.com"
	var got []string
	if err := Parse(strings.NewReader(in), func(d string) { got = append(got, d) }); err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com", "last.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestHashMatchesFNV(t *testing.T) {
	for _, s := range []string{"", "a", "example.com", "Mixed.Case.Example"} {
		h := fnv.New64a()
		h.Write([]byte(strings.ToLower(s)))
		if Hash(s) != h.Sum64() {
			t.Fatalf("hash mismatch for %q", s)
		}
	}
}
