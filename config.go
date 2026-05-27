package netident

import "net"

type databaseConfig struct {
	Version   int              `json:"version"`
	Defaults  defaultsConfig   `json:"defaults"`
	Providers []providerConfig `json:"providers"`
}

type defaultsConfig struct {
	MinScore   int `json:"min_score"`
	RuleWeight int `json:"rule_weight"`
}

type providerConfig struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Category Category    `json:"category"`
	Enabled  *bool       `json:"enabled,omitempty"`
	Rules    rulesConfig `json:"rules"`
}

type rulesConfig struct {
	PTR         []stringRuleJSON `json:"ptr,omitempty"`
	Networks    []cidrRuleJSON   `json:"networks,omitempty"`
	NetworkURLs []urlSourceJSON  `json:"network_urls,omitempty"`
	Netname     []stringRuleJSON `json:"netname,omitempty"`
	Netmail     []stringRuleJSON `json:"netmail,omitempty"`
	ASN         []asnRuleJSON    `json:"asn,omitempty"`
	ASNName     []stringRuleJSON `json:"asn_name,omitempty"`
	ASNMail     []stringRuleJSON `json:"asn_mail,omitempty"`
}

type stringRuleJSON struct {
	Match  string `json:"match"`
	Weight *int   `json:"weight,omitempty"`
}

type cidrRuleJSON struct {
	Match  string `json:"match"`
	Weight *int   `json:"weight,omitempty"`
}

type asnRuleJSON struct {
	Match  int  `json:"match"`
	Weight *int `json:"weight,omitempty"`
}

type urlSourceJSON struct {
	URL            string `json:"url"`
	Format         string `json:"format"`
	Weight         *int   `json:"weight,omitempty"`
	UpdateInterval int    `json:"update_interval,omitempty"`
	Timeout        int    `json:"timeout,omitempty"`
}

type fieldKind string

const (
	fieldPTR     fieldKind = "ptr"
	fieldNetwork fieldKind = "network"
	fieldNetname fieldKind = "netname"
	fieldNetmail fieldKind = "netmail"
	fieldASN     fieldKind = "asn"
	fieldASNName fieldKind = "asn_name"
	fieldASNMail fieldKind = "asn_mail"
)

type compiledStringRule struct {
	pattern string
	weight  int
	field   fieldKind
}

type compiledASNRule struct {
	asn    int
	weight int
}

type compiledCIDRRule struct {
	net     *net.IPNet
	weight  int
	pattern string
}
