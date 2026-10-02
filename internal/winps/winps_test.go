package winps

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var hostile = []string{
	"plain",
	"it's",
	"'; Remove-Item -Recurse -Force C:\\; '",
	"\u2019; Start-Process calc; \u2018",
	"\u201a\u201b mixed ' quotes \u2019",
	"$(Start-Process calc)",
	"$env:SystemRoot",
	"`n`r backtick",
	"line1\nline2",
	"semi; colon & amp | pipe > gt < lt",
	"@(1,2) @{a=1}",
	"C:\\Program Files\\Veyl\\veyl.exe",
	"",
	"unicode \u00e9\u4e2d\U0001F600",
}

func TestQuoteShape(t *testing.T) {
	for _, s := range hostile {
		q := Quote(s)
		if !strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'") {
			t.Fatalf("%q", q)
		}
		inner := []rune(q[1 : len(q)-1])
		for i := 0; i < len(inner); i++ {
			if isQuote(inner[i]) {
				if i+1 >= len(inner) || inner[i+1] != inner[i] {
					t.Fatalf("unescaped quote in %q", q)
				}
				i++
			}
		}
	}
	if Quote("a'b") != "'a''b'" || Quote("a\u2019b") != "'a\u2019\u2019b'" {
		t.Fatal(Quote("a'b"))
	}
}

func TestLineAndScript(t *testing.T) {
	got := Line("Set-Thing -Name %s -Port %s -On %s -List %s -Ints %s", S("x'y"), I(53), B(true), List("a", "b'c"), Ints(1, 2))
	if got != "Set-Thing -Name 'x''y' -Port 53 -On $true -List @('a', 'b''c') -Ints @(1, 2)" {
		t.Fatal(got)
	}
	var sc Script
	sc.Add("Get-Service -Name %s", S("Veyl"))
	sc.Add("'done'")
	if sc.String() != "Get-Service -Name 'Veyl'\n'done'\n" {
		t.Fatal(sc.String())
	}
}

func TestCommand(t *testing.T) {
	argv, err := Command("Get-Service -Name 'Veyl'\n'x'")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv[:5], " ") != "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command" || len(argv) != 6 {
		t.Fatalf("%q", argv)
	}
	if !strings.HasPrefix(argv[5], "$ErrorActionPreference = 'Stop'") {
		t.Fatal(argv[5])
	}
	for _, bad := range []string{"", "Write-Output \"$(calc)\"", "a\x00b", strings.Repeat("a", maxScript+1)} {
		if _, err := Command(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := Command("Write-Output " + Quote("x\"y")); err == nil {
		t.Fatal("double quote inside a literal must be refused at the command line layer")
	}
}

func pwsh(t *testing.T) string {
	t.Helper()
	candidates := []string{os.Getenv("VEYL_PWSH")}
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, p)
		}
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		argv, _ := Command("[Console]::Out.Write(" + Quote("veyl-ok") + ")")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, p, argv...).Output()
		cancel()
		if err == nil && strings.TrimSpace(string(out)) == "veyl-ok" {
			return p
		}
	}
	t.Skip("PowerShell not installed")
	return ""
}

func TestQuoteRoundTripsThroughPowerShell(t *testing.T) {
	bin := pwsh(t)
	for _, s := range hostile {
		if strings.ContainsAny(s, "\"\x00") {
			continue
		}
		var sc Script
		sc.Add("[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(%s)))", S(s))
		argv, err := Command(sc.String())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, bin, argv...).Output()
		cancel()
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		want := encode(s)
		if strings.TrimSpace(string(out)) != want {
			t.Fatalf("%q came back as %q", s, out)
		}
	}
}

func TestErrorsStopTheScript(t *testing.T) {
	bin := pwsh(t)
	argv, err := Command("Get-Item -Path " + Quote("/definitely/missing/veyl") + "\n'after'")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, argv...).CombinedOutput()
	if err == nil || strings.Contains(string(out), "after") {
		t.Fatalf("script continued after an error: %s", out)
	}
}
