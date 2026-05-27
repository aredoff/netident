package netident_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aredoff/netident"
)

func TestIdentifyGooglebotPTR(t *testing.T) {
	d := mustDetector(t, "testdata/providers_minimal.json")

	result := d.Identify(netident.Input{
		PTR: "crawl-66-249-79-1.googlebot.com",
	})

	if !result.OK {
		t.Fatal("expected match")
	}
	if result.ProviderID != "googlebot" {
		t.Fatalf("got provider %q", result.ProviderID)
	}
	if result.Score != 1000 {
		t.Fatalf("score = %d, want 1000", result.Score)
	}
}

func TestGooglebotBeatsGCPNetname(t *testing.T) {
	d := mustDetector(t, "testdata/providers_minimal.json")

	result := d.Identify(netident.Input{
		PTR:     "crawl-66-249-79-1.googlebot.com",
		Netname: "GOOGLE-CLOUD",
	})

	if result.ProviderID != "googlebot" {
		t.Fatalf("got provider %q, want googlebot", result.ProviderID)
	}
	if result.Score != 1000 {
		t.Fatalf("score = %d, want 1000", result.Score)
	}
}

func TestGooglebotNetworkMatch(t *testing.T) {
	d := mustDetector(t, "testdata/providers_minimal.json")

	ip := net.ParseIP("66.249.79.1")
	result := d.Identify(netident.Input{IP: ip})

	if result.ProviderID != "googlebot" {
		t.Fatalf("got provider %q", result.ProviderID)
	}
	if result.Score != 900 {
		t.Fatalf("score = %d, want 900", result.Score)
	}
}

func TestGCPVM(t *testing.T) {
	d := mustDetector(t, "testdata/providers_minimal.json")

	result := d.Identify(netident.Input{
		PTR: "34.102.136.93.bc.googleusercontent.com",
	})

	if result.ProviderID != "gcp" {
		t.Fatalf("got provider %q, want gcp", result.ProviderID)
	}
	if result.Score != 50 {
		t.Fatalf("score = %d, want 50", result.Score)
	}
}

func TestDefaultRuleWeight(t *testing.T) {
	d := mustDetector(t, "testdata/providers_minimal.json")

	result := d.Identify(netident.Input{
		PTR:     "server.example.your-server.de",
		Netname: "HETZNER-DC",
	})

	if result.ProviderID != "hetzner" {
		t.Fatalf("got provider %q", result.ProviderID)
	}
	if result.Score != 20 {
		t.Fatalf("score = %d, want 20", result.Score)
	}
}

func TestCaseInsensitiveGlob(t *testing.T) {
	d := mustDetector(t, "testdata/providers_minimal.json")

	result := d.Identify(netident.Input{
		PTR: "crawl-66-249-79-1.GOOGLEBOT.COM",
	})

	if !result.OK || result.ProviderID != "googlebot" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEmptyFieldsIgnored(t *testing.T) {
	d := mustDetector(t, "testdata/providers_minimal.json")

	result := d.Identify(netident.Input{})
	if result.OK {
		t.Fatalf("expected no match, got %+v", result)
	}
}

func TestInvalidGlobRejected(t *testing.T) {
	cfg := []byte(`{
		"version": 1,
		"providers": [{
			"id": "bad",
			"name": "Bad",
			"category": "other",
			"rules": {"ptr": [{"match": "[invalid"}]}
		}]
	}`)
	_, err := netident.NewFromJSON(bytes.NewReader(cfg))
	if err == nil {
		t.Fatal("expected error for invalid glob")
	}
}

func TestInvalidCIDRRejected(t *testing.T) {
	cfg := []byte(`{
		"version": 1,
		"providers": [{
			"id": "bad",
			"name": "Bad",
			"category": "other",
			"rules": {"networks": [{"match": "not-a-cidr"}]}
		}]
	}`)
	_, err := netident.NewFromJSON(bytes.NewReader(cfg))
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestZeroWeightRejected(t *testing.T) {
	cfg := []byte(`{
		"version": 1,
		"providers": [{
			"id": "bad",
			"name": "Bad",
			"category": "other",
			"rules": {"ptr": [{"match": "*", "weight": 0}]}
		}]
	}`)
	_, err := netident.NewFromJSON(bytes.NewReader(cfg))
	if err == nil {
		t.Fatal("expected error for zero weight")
	}
}

func TestStartCloseWithMockURL(t *testing.T) {
	body, err := os.ReadFile("testdata/googlebot.json")
	if err != nil {
		t.Fatal(err)
	}

	srv := newTestHTTPServer(t, body)
	defer srv.Close()

	cfg := []byte(`{
		"version": 1,
		"providers": [{
			"id": "googlebot",
			"name": "Google Bot",
			"category": "bot",
			"rules": {
				"network_urls": [{
					"url": "` + srv.URL + `",
					"format": "google_prefixes",
					"weight": 900,
					"update_interval": 60,
					"timeout": 5
				}]
			}
		}]
	}`)

	cacheDir := t.TempDir()
	d, err := netident.NewFromJSON(bytes.NewReader(cfg), netident.WithCacheDir(cacheDir))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := d.Ready(readyCtx); err != nil {
		t.Fatal(err)
	}

	ip := net.ParseIP("66.249.79.1")
	result := d.Identify(netident.Input{IP: ip})
	if !result.OK || result.Score != 900 {
		t.Fatalf("unexpected result: %+v", result)
	}

	ip6 := net.ParseIP("2001:4860:4801:15::1")
	result = d.Identify(netident.Input{IP: ip6})
	if !result.OK || result.Score != 900 {
		t.Fatalf("unexpected ipv6 result: %+v", result)
	}

	cancel()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedDefaultConfig(t *testing.T) {
	d, err := netident.New()
	if err != nil {
		t.Fatal(err)
	}

	result := d.Identify(netident.Input{
		PTR: "crawl-66-249-79-1.googlebot.com",
	})
	if result.ProviderID != "googlebot" {
		t.Fatalf("got %q", result.ProviderID)
	}
}

func mustDetector(t *testing.T, path string) *netident.Detector {
	t.Helper()
	d, err := netident.NewFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

type httpHandler []byte

func (h httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(h)
}
