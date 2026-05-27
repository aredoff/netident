package netident

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/aredoff/netident/internal/defaultproviders"
)

func New(opts ...Option) (*Detector, error) {
	o := applyOptions(opts)
	if len(o.configData) == 0 {
		o.configData = defaultproviders.JSON
	}
	return NewFromJSON(bytes.NewReader(o.configData), opts...)
}

func NewFromFile(path string, opts ...Option) (*Detector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	o := applyOptions(opts)
	o.configData = data
	return NewFromJSON(bytes.NewReader(data), opts...)
}

func NewFromConfig(cfg Config, opts ...Option) (*Detector, error) {
	return buildDetector(cfg, applyOptions(opts))
}

func NewFromJSON(r io.Reader, opts ...Option) (*Detector, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	return buildDetector(cfg, applyOptions(opts))
}

func buildDetector(cfg Config, o options) (*Detector, error) {
	if cfg.Version != 1 {
		return nil, fmt.Errorf("unsupported config version %d", cfg.Version)
	}

	defaults := normalizeDefaults(cfg.Defaults)
	if err := validateConfig(&cfg, defaults); err != nil {
		return nil, err
	}

	d := &Detector{
		minScore:   defaults.MinScore,
		httpClient: o.httpClient,
		logger:     o.logger,
		cache:      o.cache,
	}

	providers, sources, err := compileProviders(&cfg, defaults)
	if err != nil {
		return nil, err
	}
	d.providers = providers
	d.sources = sources

	if d.cache != nil {
		for _, s := range d.sources {
			if err := d.loadSourceFromCache(s); err != nil {
				d.logger.Debug("cache load failed", "url", s.url, "error", err)
			}
		}
	}

	return d, nil
}

func normalizeDefaults(d Defaults) Defaults {
	if d.MinScore <= 0 {
		d.MinScore = 1
	}
	if d.RuleWeight <= 0 {
		d.RuleWeight = 10
	}
	return d
}

func resolveWeight(w *int, defaultWeight int) (int, error) {
	if w == nil {
		return defaultWeight, nil
	}
	if *w <= 0 {
		return 0, fmt.Errorf("weight must be positive, got %d", *w)
	}
	return *w, nil
}

func validateConfig(cfg *Config, defaults Defaults) error {
	seen := make(map[string]struct{}, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if p.ID == "" {
			return fmt.Errorf("provider id is required")
		}
		if _, ok := seen[p.ID]; ok {
			return fmt.Errorf("duplicate provider id %q", p.ID)
		}
		seen[p.ID] = struct{}{}
		if p.Name == "" {
			return fmt.Errorf("provider %q: name is required", p.ID)
		}
		if p.Category == "" {
			return fmt.Errorf("provider %q: category is required", p.ID)
		}
		if err := validateRules(p.ID, &p.Rules, defaults); err != nil {
			return err
		}
	}
	return nil
}

func validateRules(providerID string, rules *Rules, defaults Defaults) error {
	for _, r := range rules.PTR {
		if err := validateStringRule(providerID, "ptr", r, defaults); err != nil {
			return err
		}
	}
	for _, r := range rules.Netname {
		if err := validateStringRule(providerID, "netname", r, defaults); err != nil {
			return err
		}
	}
	for _, r := range rules.Netmail {
		if err := validateStringRule(providerID, "netmail", r, defaults); err != nil {
			return err
		}
	}
	for _, r := range rules.ASNName {
		if err := validateStringRule(providerID, "asn_name", r, defaults); err != nil {
			return err
		}
	}
	for _, r := range rules.ASNMail {
		if err := validateStringRule(providerID, "asn_mail", r, defaults); err != nil {
			return err
		}
	}
	for _, r := range rules.Networks {
		if r.Match == "" {
			return fmt.Errorf("provider %q: networks match is required", providerID)
		}
		if _, err := parseCIDR(r.Match); err != nil {
			return fmt.Errorf("provider %q: invalid CIDR %q: %w", providerID, r.Match, err)
		}
		if _, err := resolveWeight(r.Weight, defaults.RuleWeight); err != nil {
			return fmt.Errorf("provider %q: networks: %w", providerID, err)
		}
	}
	for _, r := range rules.ASN {
		if r.Match <= 0 {
			return fmt.Errorf("provider %q: asn match must be positive", providerID)
		}
		if _, err := resolveWeight(r.Weight, defaults.RuleWeight); err != nil {
			return fmt.Errorf("provider %q: asn: %w", providerID, err)
		}
	}
	for _, u := range rules.NetworkURLs {
		if u.URL == "" {
			return fmt.Errorf("provider %q: network_urls url is required", providerID)
		}
		if _, err := url.Parse(u.URL); err != nil {
			return fmt.Errorf("provider %q: invalid url %q: %w", providerID, u.URL, err)
		}
		if u.Format != "cidr_list" && u.Format != "google_prefixes" {
			return fmt.Errorf("provider %q: unknown format %q", providerID, u.Format)
		}
		if u.UpdateInterval != 0 && u.UpdateInterval < 60 {
			return fmt.Errorf("provider %q: update_interval must be >= 60", providerID)
		}
		if _, err := resolveWeight(u.Weight, defaults.RuleWeight); err != nil {
			return fmt.Errorf("provider %q: network_urls: %w", providerID, err)
		}
	}
	return nil
}

func validateStringRule(providerID, field string, r StringRule, defaults Defaults) error {
	if r.Match == "" {
		return fmt.Errorf("provider %q: %s match is required", providerID, field)
	}
	if err := validateGlob(r.Match); err != nil {
		return fmt.Errorf("provider %q: invalid glob %q in %s: %w", providerID, r.Match, field, err)
	}
	if _, err := resolveWeight(r.Weight, defaults.RuleWeight); err != nil {
		return fmt.Errorf("provider %q: %s: %w", providerID, field, err)
	}
	return nil
}

func compileProviders(cfg *Config, defaults Defaults) ([]*compiledProvider, []*urlSource, error) {
	var providers []*compiledProvider
	var allSources []*urlSource

	for _, p := range cfg.Providers {
		enabled := true
		if p.Enabled != nil {
			enabled = *p.Enabled
		}
		if !enabled {
			continue
		}

		cp := &compiledProvider{
			id:       p.ID,
			name:     p.Name,
			category: p.Category,
		}

		for _, r := range p.Rules.PTR {
			w, _ := resolveWeight(r.Weight, defaults.RuleWeight)
			cp.stringRules = append(cp.stringRules, compiledStringRule{pattern: r.Match, weight: w, field: fieldPTR})
		}
		for _, r := range p.Rules.Netname {
			w, _ := resolveWeight(r.Weight, defaults.RuleWeight)
			cp.stringRules = append(cp.stringRules, compiledStringRule{pattern: r.Match, weight: w, field: fieldNetname})
		}
		for _, r := range p.Rules.Netmail {
			w, _ := resolveWeight(r.Weight, defaults.RuleWeight)
			cp.stringRules = append(cp.stringRules, compiledStringRule{pattern: r.Match, weight: w, field: fieldNetmail})
		}
		for _, r := range p.Rules.ASNName {
			w, _ := resolveWeight(r.Weight, defaults.RuleWeight)
			cp.stringRules = append(cp.stringRules, compiledStringRule{pattern: r.Match, weight: w, field: fieldASNName})
		}
		for _, r := range p.Rules.ASNMail {
			w, _ := resolveWeight(r.Weight, defaults.RuleWeight)
			cp.stringRules = append(cp.stringRules, compiledStringRule{pattern: r.Match, weight: w, field: fieldASNMail})
		}
		for _, r := range p.Rules.Networks {
			w, _ := resolveWeight(r.Weight, defaults.RuleWeight)
			n, _ := parseCIDR(r.Match)
			cp.cidrRules = append(cp.cidrRules, compiledCIDRRule{net: n, weight: w, pattern: r.Match})
		}
		for _, r := range p.Rules.ASN {
			w, _ := resolveWeight(r.Weight, defaults.RuleWeight)
			cp.asnRules = append(cp.asnRules, compiledASNRule{asn: r.Match, weight: w})
		}
		for _, u := range p.Rules.NetworkURLs {
			w, _ := resolveWeight(u.Weight, defaults.RuleWeight)
			interval := u.UpdateInterval
			if interval == 0 {
				interval = 86400
			}
			timeout := u.Timeout
			if timeout == 0 {
				timeout = 30
			}
			src := &urlSource{
				url:            u.URL,
				format:         u.Format,
				weight:         w,
				updateInterval: time.Duration(interval) * time.Second,
				timeout:        time.Duration(timeout) * time.Second,
				providerID:     p.ID,
			}
			cp.urlSources = append(cp.urlSources, src)
			allSources = append(allSources, src)
		}

		if hasRules(cp) {
			providers = append(providers, cp)
		}
	}

	return providers, allSources, nil
}

func hasRules(p *compiledProvider) bool {
	return len(p.stringRules) > 0 || len(p.asnRules) > 0 || len(p.cidrRules) > 0 || len(p.urlSources) > 0
}

func (d *Detector) loadSourceFromCache(s *urlSource) error {
	if d.cache == nil {
		return errCacheMiss
	}
	data, updated, err := d.cache.Load(s.url)
	if err != nil {
		return err
	}
	if time.Since(updated) > s.updateInterval {
		return fmt.Errorf("cache outdated")
	}
	nets, err := unmarshalNets(data)
	if err != nil {
		return err
	}
	s.setNets(nets)
	return nil
}
