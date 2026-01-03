package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Mode string

const (
	ModeOff            Mode = "off"
	ModeBundleOnly     Mode = "bundle_only"
	ModeProtectPrefixes Mode = "protect_prefixes"
	ModeAll            Mode = "all"
	ModeVTLSPrefix     Mode = "vtls_prefix"
)

type Config struct {
	ListenAddr string
	Upstream   *url.URL

	Mode Mode

	// ProtectPrefixes are matched against the inbound request path.
	ProtectPrefixes []string

	// VTLSPrefix is the route prefix (default "/vtls") that, if matched,
	// will be treated as protected and will be stripped before proxying upstream.
	VTLSPrefix string

	// DomainOverride, if set, is used as the bundle "domain" regardless of Host header.
	DomainOverride string

	// BundleTTL controls issued_at/expires_at.
	BundleTTL time.Duration
}

func FromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:    getenv("VTLS_LISTEN_ADDR", "127.0.0.1:8181"),
		VTLSPrefix:    getenv("VTLS_PREFIX", "/vtls"),
		DomainOverride: strings.TrimSpace(os.Getenv("VTLS_DOMAIN")),
		Mode:          Mode(getenv("VTLS_MODE", string(ModeBundleOnly))),
	}

	upstreamRaw := strings.TrimSpace(os.Getenv("APP_UPSTREAM"))
	if upstreamRaw == "" {
		return nil, fmt.Errorf("APP_UPSTREAM is required (e.g. http://127.0.0.1:3000)")
	}
	u, err := url.Parse(upstreamRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid APP_UPSTREAM: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("APP_UPSTREAM must be http(s), got %q", u.Scheme)
	}
	cfg.Upstream = u

	ttlSecs := strings.TrimSpace(getenv("VTLS_BUNDLE_TTL_SECS", "300"))
	ttlN, err := strconv.Atoi(ttlSecs)
	if err != nil || ttlN <= 0 {
		return nil, fmt.Errorf("VTLS_BUNDLE_TTL_SECS must be a positive integer, got %q", ttlSecs)
	}
	cfg.BundleTTL = time.Duration(ttlN) * time.Second

	cfg.ProtectPrefixes = splitCSV(getenv("VTLS_PROTECT_PREFIXES", ""))

	switch cfg.Mode {
	case ModeOff, ModeBundleOnly, ModeProtectPrefixes, ModeAll, ModeVTLSPrefix:
	default:
		return nil, fmt.Errorf("invalid VTLS_MODE %q (expected off|bundle_only|protect_prefixes|vtls_prefix|all)", cfg.Mode)
	}
	if cfg.VTLSPrefix == "" || !strings.HasPrefix(cfg.VTLSPrefix, "/") {
		return nil, fmt.Errorf("VTLS_PREFIX must start with '/', got %q", cfg.VTLSPrefix)
	}
	return cfg, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		out = append(out, p)
	}
	return out
}

func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}


