package panel

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/veylvpn/backend/internal/panelcfg"
)

func TestHookHelper(t *testing.T) {
	if os.Getenv("VEYL_HOOK_HELPER") != "1" {
		t.Skip("helper process only")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Exit(Main(args[1:]))
}

func writeFakeCertbot(t *testing.T, paths panelcfg.Paths) string {
	t.Helper()
	dir := t.TempDir()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "veyl")
	ws := "#!/bin/sh\nVEYL_HOOK_HELPER=1 VEYL_PANEL_RUN='" + paths.Run + "' VEYL_PANEL_DATA='" + paths.Data + "' exec '" + bin + "' -test.run='^TestHookHelper$' -- \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(ws), 0o755); err != nil {
		t.Fatal(err)
	}
	cb := filepath.Join(dir, "certbot")
	script := `#!/bin/bash
set -eu
auth=""
cleanup=""
domain=""
while [ $# -gt 0 ]; do
	case "$1" in
	--manual-auth-hook) auth="$2"; shift 2 ;;
	--manual-cleanup-hook) cleanup="$2"; shift 2 ;;
	-d) domain="$2"; shift 2 ;;
	*) shift ;;
	esac
done
export CERTBOT_DOMAIN="$domain"
export CERTBOT_VALIDATION="dGVzdC12YWxpZGF0aW9uLXRva2VuLWZha2UtY2VydGJvdA"
if $auth; then echo auth-ok; else echo auth-failed; exit 1; fi
$cleanup
echo cleanup-done
`
	if err := os.WriteFile(cb, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VEYL_FAKE_WRAPPER", wrapper)
	return cb
}

func runScript(ctx context.Context, certbot string, paths panelcfg.Paths) (string, error) {
	w := os.Getenv("VEYL_FAKE_WRAPPER")
	cmd := exec.CommandContext(ctx, certbot, "certonly", "--non-interactive", "--agree-tos", "-m", "ops@example.com", "--manual", "--preferred-challenges", "dns",
		"--manual-auth-hook", w+" panel acme-auth", "--manual-cleanup-hook", w+" panel acme-cleanup", "-d", "control.example.com")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
