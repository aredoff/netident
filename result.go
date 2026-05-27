package netident

type Category string

const (
	CategoryBot     Category = "bot"
	CategoryCloud   Category = "cloud"
	CategoryCDN     Category = "cdn"
	CategoryHosting Category = "hosting"
	CategoryISP     Category = "isp"
	CategoryOther   Category = "other"
)

func (c Category) priority() int {
	switch c {
	case CategoryBot:
		return 6
	case CategoryCloud:
		return 5
	case CategoryCDN:
		return 4
	case CategoryHosting:
		return 3
	case CategoryISP:
		return 2
	default:
		return 1
	}
}

type Match struct {
	Field   string
	Pattern string
	Weight  int
}

type Result struct {
	ProviderID string
	Name       string
	Category   Category
	Score      int
	Matches    []Match
	OK         bool
}
