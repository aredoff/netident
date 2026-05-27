package netident

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
)

var cidrLinePattern = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?`)

type googlePrefixesResponse struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

func parseCIDRList(r io.Reader) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, match := range cidrLinePattern.FindAllString(line, -1) {
			n, err := parseCIDR(match)
			if err != nil {
				continue
			}
			nets = append(nets, n)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nets, nil
}

func parseGooglePrefixes(r io.Reader) ([]*net.IPNet, error) {
	var resp googlePrefixesResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, err
	}
	var nets []*net.IPNet
	for _, p := range resp.Prefixes {
		for _, prefix := range []string{p.IPv4Prefix, p.IPv6Prefix} {
			if prefix == "" {
				continue
			}
			n, err := parseCIDR(prefix)
			if err != nil {
				return nil, fmt.Errorf("parse google prefix %q: %w", prefix, err)
			}
			nets = append(nets, n)
		}
	}
	return nets, nil
}

func parseURLBody(format string, r io.Reader) ([]*net.IPNet, error) {
	switch format {
	case "cidr_list":
		return parseCIDRList(r)
	case "google_prefixes":
		return parseGooglePrefixes(r)
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}

func parseCIDR(s string) (*net.IPNet, error) {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", s)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func ipInNets(ip net.IP, nets []*net.IPNet) (bool, string) {
	for _, n := range nets {
		if n.Contains(ip) {
			return true, n.String()
		}
	}
	return false, ""
}

func marshalNets(nets []*net.IPNet) ([]byte, error) {
	strs := make([]string, len(nets))
	for i, n := range nets {
		strs[i] = n.String()
	}
	return json.Marshal(strs)
}

func unmarshalNets(data []byte) ([]*net.IPNet, error) {
	var strs []string
	if err := json.Unmarshal(data, &strs); err != nil {
		return nil, err
	}
	nets := make([]*net.IPNet, 0, len(strs))
	for _, s := range strs {
		n, err := parseCIDR(s)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return nets, nil
}
