package admin

import (
	"os"
	"testing"

	"github.com/veylvpn/backend/internal/pki/pkitest"
)

func TestMain(m *testing.M) {
	os.Exit(pkitest.Main(m))
}
