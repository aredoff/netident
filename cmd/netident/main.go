package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/aredoff/netident"
)

var version = "dev"

type runOptions struct {
	configPath string
	cacheDir   string
	input      netident.Input
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	validatePath := flag.String("validate", "", "validate providers.json and exit")
	configPath := flag.String("config", "", "path to providers.json (default: embedded production config)")
	cacheDir := flag.String("cache-dir", "", "directory for network URL cache (default: $TMPDIR/netident-cache)")
	ipStr := flag.String("ip", "", "IP address")
	ptr := flag.String("ptr", "", "PTR record")
	netname := flag.String("netname", "", "WHOIS netname")
	netmail := flag.String("netmail", "", "WHOIS netmail")
	asnStr := flag.String("asn", "", "ASN number")
	asnName := flag.String("asn-name", "", "ASN organization name")
	asnMail := flag.String("asn-mail", "", "ASN abuse email")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if *validatePath != "" {
		if err := validateConfigFile(*validatePath, *cacheDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("config ok: %s\n", *validatePath)
		return
	}

	input, err := parseInput(*ipStr, *ptr, *netname, *netmail, *asnStr, *asnName, *asnMail)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := run(runOptions{
		configPath: *configPath,
		cacheDir:   *cacheDir,
		input:      input,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseInput(ipStr, ptr, netname, netmail, asnStr, asnName, asnMail string) (netident.Input, error) {
	var input netident.Input

	if ipStr != "" {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return input, fmt.Errorf("invalid IP address %q", ipStr)
		}
		input.IP = ip
	}

	input.PTR = ptr
	input.Netname = netname
	input.Netmail = netmail
	input.ASNName = asnName
	input.ASNMail = asnMail

	if asnStr != "" {
		asn, err := strconv.Atoi(asnStr)
		if err != nil || asn <= 0 {
			return input, fmt.Errorf("invalid ASN %q", asnStr)
		}
		input.ASN = &asn
	}

	if input.IP == nil && input.PTR == "" && input.Netname == "" && input.Netmail == "" &&
		input.ASN == nil && input.ASNName == "" && input.ASNMail == "" {
		return input, fmt.Errorf("at least one input field is required (-ip, -ptr, -netname, -netmail, -asn, -asn-name, -asn-mail)")
	}

	return input, nil
}

func run(opts runOptions) error {
	d, err := newDetector(opts.configPath, opts.cacheDir)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := d.Start(ctx); err != nil {
		return err
	}
	defer d.Close()

	result := d.Identify(opts.input)
	if !result.OK {
		fmt.Println("no match")
		return nil
	}

	fmt.Printf("provider=%s name=%q category=%s score=%d\n", result.ProviderID, result.Name, result.Category, result.Score)
	for _, m := range result.Matches {
		fmt.Printf("  %s %q weight=%d\n", m.Field, m.Pattern, m.Weight)
	}
	return nil
}

func newDetector(configPath, cacheDir string) (*netident.Detector, error) {
	opts := []netident.Option{
		netident.WithCacheDir(resolveCacheDir(cacheDir)),
	}

	if configPath == "" {
		return netident.New(opts...)
	}

	return netident.NewFromFile(configPath, opts...)
}

func resolveCacheDir(cacheDir string) string {
	if cacheDir != "" {
		return cacheDir
	}
	return filepath.Join(os.TempDir(), "netident-cache")
}

func validateConfigFile(path, cacheDir string) error {
	d, err := newDetector(path, cacheDir)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := d.Start(ctx); err != nil {
		return err
	}
	defer d.Close()

	d.Identify(netident.Input{
		PTR: "netident-validation-probe.example.com",
	})

	return nil
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: netident [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Identify network providers, bots, and cloud platforms by IP, PTR, WHOIS, and ASN data.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
}
