package app

import (
	"github.com/veylvpn/backend/internal/agentapi"
	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
)

var Version = "0.2.0-dev"

type Mgmt interface {
	Online() (map[string]bool, error)
	Kill(cn string) error
}

type Deps struct {
	Paths    config.Paths
	Settings *config.Live
	Store    *store.Store
	CA       *pki.CA
	Mgmt     Mgmt
	Agent    agentapi.Client
}
