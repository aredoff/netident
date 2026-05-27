package netident

import "net"

type Config struct {
	Version   int        `json:"version"`
	Defaults  Defaults   `json:"defaults"`
	Providers []Provider `json:"providers"`
}

type Defaults struct {
	MinScore   int `json:"min_score"`
	RuleWeight int `json:"rule_weight"`
}

type Provider struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category Category `json:"category"`
	Enabled  *bool    `json:"enabled,omitempty"`
	Rules    Rules    `json:"rules"`
}

type Rules struct {
	PTR         []StringRule  `json:"ptr,omitempty"`
	Networks    []CIDRRule    `json:"networks,omitempty"`
	NetworkURLs []URLSource   `json:"network_urls,omitempty"`
	Netname     []StringRule  `json:"netname,omitempty"`
	Netmail     []StringRule  `json:"netmail,omitempty"`
	ASN         []ASNRule     `json:"asn,omitempty"`
	ASNName     []StringRule  `json:"asn_name,omitempty"`
	ASNMail     []StringRule  `json:"asn_mail,omitempty"`
}

type StringRule struct {
	Match  string `json:"match"`
	Weight *int   `json:"weight,omitempty"`
}

type CIDRRule struct {
	Match  string `json:"match"`
	Weight *int   `json:"weight,omitempty"`
}

type ASNRule struct {
	Match  int  `json:"match"`
	Weight *int `json:"weight,omitempty"`
}

type URLSource struct {
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
