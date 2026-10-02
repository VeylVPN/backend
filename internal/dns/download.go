package dns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/veylvpn/backend/internal/config"
)

var BlocklistSources = map[string][]string{
	config.CatAds: {
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
	},
	config.CatTrackers: {
		"https://raw.githubusercontent.com/mullvad/dns-blocklists/main/output/doh/doh_privacy.txt",
	},
	config.CatMalware: {
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
		"https://urlhaus.abuse.ch/downloads/hostfile/",
	},
	config.CatAdult: {
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
	},
	config.CatGambling: {
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.medium-onlydomains.txt",
	},
	config.CatSocial: {
		"https://raw.githubusercontent.com/mullvad/dns-blocklists/main/output/doh/doh_social.txt",
	},
}

var (
	maxSourceBytes int64 = 64 << 20
	sourceTimeout        = 60 * time.Second
	minEntries           = 100
)

func Download(ctx context.Context, dir string, client *http.Client) (map[string]int, error) {
	if client == nil {
		client = &http.Client{}
	}
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("redirect to non-https url")
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	var errs []error
	for _, cat := range config.Categories {
		srcs := BlocklistSources[cat]
		if len(srcs) == 0 {
			continue
		}
		set := map[string]struct{}{}
		ok := 0
		for _, u := range srcs {
			if err := fetchSource(ctx, &c, u, set); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", cat, err))
				continue
			}
			ok++
		}
		if ok == 0 {
			continue
		}
		if len(set) < minEntries {
			errs = append(errs, fmt.Errorf("%s: only %d entries, keeping previous list", cat, len(set)))
			continue
		}
		names := make([]string, 0, len(set))
		for d := range set {
			names = append(names, d)
		}
		slices.Sort(names)
		if err := writeList(ListPath(dir, cat), names); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", cat, err))
			continue
		}
		counts[cat] = len(names)
	}
	return counts, errors.Join(errs...)
}

func fetchSource(ctx context.Context, c *http.Client, raw string, set map[string]struct{}) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("source must be an https url")
	}
	ctx, cancel := context.WithTimeout(ctx, sourceTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: status %d", u.Host, resp.StatusCode)
	}
	lr := &io.LimitedReader{R: resp.Body, N: maxSourceBytes + 1}
	local := map[string]struct{}{}
	if err := Parse(lr, func(d string) { local[d] = struct{}{} }); err != nil {
		return fmt.Errorf("read %s: %w", u.Host, err)
	}
	if lr.N <= 0 {
		return fmt.Errorf("fetch %s: source larger than %d bytes", u.Host, maxSourceBytes)
	}
	for d := range local {
		set[d] = struct{}{}
	}
	return nil
}

func writeList(path string, names []string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".veyl-list-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	w := bufio.NewWriterSize(tmp, 256*1024)
	for _, d := range names {
		w.WriteString(d)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
