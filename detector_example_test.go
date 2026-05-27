package netident_test

import (
	"fmt"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/aredoff/netident"
)

func ExampleNew_identify() {
	d, err := netident.New()
	if err != nil {
		fmt.Println(err)
		return
	}

	result := d.Identify(netident.Input{
		PTR: "crawl-66-249-79-1.googlebot.com",
	})

	fmt.Println(result.ProviderID, result.Score, result.OK)
	// Output: googlebot 1000 true
}

func ExampleDetector_IdentifyAll() {
	d, err := netident.NewFromFile("testdata/providers_minimal.json")
	if err != nil {
		fmt.Println(err)
		return
	}

	ip := net.ParseIP("66.249.79.1")
	all := d.IdentifyAll(netident.Input{IP: ip})
	if len(all) == 0 {
		fmt.Println("none")
		return
	}
	fmt.Println(all[0].ProviderID, all[0].Score)
	// Output: googlebot 900
}

func newTestHTTPServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(httpHandler(body))
}
