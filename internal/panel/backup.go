package panel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/veylvpn/backend/internal/backup"
	"github.com/veylvpn/backend/internal/panelcfg"
)

var backupSet = []backup.File{
	{Name: "panel.json", Perm: 0o600, Required: true},
	{Name: "secret.key", Perm: 0o600, Required: true},
	{Name: "site.json", Perm: 0o640},
}

var ErrPanelExists = errors.New("this panel already has data; restore needs -force")

func CreateBackup(paths panelcfg.Paths, db *DB, pass string) ([]byte, error) {
	content := map[string][]byte{}
	var err error
	if db != nil {
		content["panel.json"], err = db.Raw()
	} else {
		content["panel.json"], err = os.ReadFile(paths.DB())
	}
	if err != nil {
		return nil, err
	}
	if content["secret.key"], err = os.ReadFile(paths.Secret()); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(paths.Site()); err == nil {
		content["site.json"] = b
	}
	return backup.CreateBundle(backupSet, content, pass)
}

func RestoreBackup(paths panelcfg.Paths, data []byte, pass string, force bool) ([]string, error) {
	content, err := backup.OpenBundle(backupSet, data, pass)
	if err != nil {
		return nil, err
	}
	var probe struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(content["panel.json"], &probe) != nil || probe.Schema < 1 {
		return nil, backup.ErrFormat
	}
	if len(content["secret.key"]) != 32 {
		return nil, backup.ErrFormat
	}
	if b, ok := content["site.json"]; ok {
		var s panelcfg.Site
		if json.Unmarshal(b, &s) != nil || s.Validate() != nil {
			return nil, backup.ErrFormat
		}
	}
	if _, err := os.Stat(paths.DB()); err == nil && !force {
		return nil, ErrPanelExists
	}
	var written []string
	for _, f := range backupSet {
		b, ok := content[f.Name]
		if !ok {
			continue
		}
		dst := filepath.Join(paths.Data, f.Name)
		if err := panelcfg.WriteFile(dst, b, f.Perm); err != nil {
			return written, err
		}
		written = append(written, dst)
	}
	return written, nil
}
