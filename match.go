package netident

import (
	"cmp"
	"slices"
	"strconv"
)

func (d *Detector) Identify(input Input) Result {
	all := d.IdentifyAll(input)
	if len(all) == 0 {
		return Result{}
	}
	return all[0]
}

func (d *Detector) IdentifyAll(input Input) []Result {
	results := make([]Result, 0, len(d.providers))
	for _, p := range d.providers {
		if r, ok := d.scoreProvider(p, input); ok {
			results = append(results, r)
		}
	}

	slices.SortFunc(results, func(a, b Result) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		if c := cmp.Compare(b.Category.priority(), a.Category.priority()); c != 0 {
			return c
		}
		if c := cmp.Compare(len(b.Matches), len(a.Matches)); c != 0 {
			return c
		}
		return cmp.Compare(a.ProviderID, b.ProviderID)
	})

	return results
}

func (d *Detector) scoreProvider(p *compiledProvider, input Input) (Result, bool) {
	score := 0
	matches := make([]Match, 0, 8)

	for _, r := range p.stringRules {
		value, ok := stringFieldValue(input, r.field)
		if !ok {
			continue
		}
		matched, err := globMatch(r.pattern, value)
		if err != nil || !matched {
			continue
		}
		score += r.weight
		matches = append(matches, Match{Field: string(r.field), Pattern: r.pattern, Weight: r.weight})
	}

	if input.ASN != nil {
		for _, r := range p.asnRules {
			if *input.ASN != r.asn {
				continue
			}
			score += r.weight
			matches = append(matches, Match{Field: string(fieldASN), Pattern: strconv.Itoa(r.asn), Weight: r.weight})
		}
	}

	if input.IP != nil {
		for _, r := range p.cidrRules {
			if !r.net.Contains(input.IP) {
				continue
			}
			score += r.weight
			matches = append(matches, Match{Field: string(fieldNetwork), Pattern: r.pattern, Weight: r.weight})
		}
		for _, s := range p.urlSources {
			nets := s.getNets()
			if len(nets) == 0 {
				continue
			}
			ok, pattern := ipInNets(input.IP, nets)
			if !ok {
				continue
			}
			score += s.weight
			matches = append(matches, Match{Field: string(fieldNetwork), Pattern: s.url + ":" + pattern, Weight: s.weight})
		}
	}

	if score == 0 || score < d.minScore {
		return Result{}, false
	}

	return Result{
		ProviderID: p.id,
		Name:       p.name,
		Category:   p.category,
		Score:      score,
		Matches:    matches,
		OK:         true,
	}, true
}

func stringFieldValue(input Input, field fieldKind) (string, bool) {
	switch field {
	case fieldPTR:
		if input.PTR == "" {
			return "", false
		}
		return input.PTR, true
	case fieldNetname:
		if input.Netname == "" {
			return "", false
		}
		return input.Netname, true
	case fieldNetmail:
		if input.Netmail == "" {
			return "", false
		}
		return input.Netmail, true
	case fieldASNName:
		if input.ASNName == "" {
			return "", false
		}
		return input.ASNName, true
	case fieldASNMail:
		if input.ASNMail == "" {
			return "", false
		}
		return input.ASNMail, true
	default:
		return "", false
	}
}
