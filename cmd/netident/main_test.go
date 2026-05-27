package main

import "testing"

func TestValidateConfigFile(t *testing.T) {
	if err := validateConfigFile("../../testdata/providers_minimal.json", ""); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConfigFileInvalid(t *testing.T) {
	err := validateConfigFile("../../testdata/does-not-exist.json", "")
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestParseInputRequiresField(t *testing.T) {
	_, err := parseInput("", "", "", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseInputAllFields(t *testing.T) {
	input, err := parseInput(
		"66.249.79.1",
		"crawl-66-249-79-1.googlebot.com",
		"GOOGLE",
		"abuse@google.com",
		"15169",
		"GOOGLE",
		"abuse@google.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.IP.String() != "66.249.79.1" {
		t.Fatalf("ip = %q", input.IP)
	}
	if input.PTR != "crawl-66-249-79-1.googlebot.com" {
		t.Fatalf("ptr = %q", input.PTR)
	}
	if input.Netname != "GOOGLE" {
		t.Fatalf("netname = %q", input.Netname)
	}
	if input.Netmail != "abuse@google.com" {
		t.Fatalf("netmail = %q", input.Netmail)
	}
	if input.ASN == nil || *input.ASN != 15169 {
		t.Fatalf("asn = %v", input.ASN)
	}
	if input.ASNName != "GOOGLE" {
		t.Fatalf("asn_name = %q", input.ASNName)
	}
	if input.ASNMail != "abuse@google.com" {
		t.Fatalf("asn_mail = %q", input.ASNMail)
	}
}

func TestParseInputInvalidIP(t *testing.T) {
	_, err := parseInput("not-an-ip", "example.com", "", "", "", "", "")
	if err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func TestParseInputInvalidASN(t *testing.T) {
	_, err := parseInput("", "", "", "", "abc", "", "")
	if err == nil {
		t.Fatal("expected invalid ASN error")
	}
}

func TestParseInputIPv6(t *testing.T) {
	input, err := parseInput("2001:4860:4801::", "", "", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if input.IP.To16() == nil {
		t.Fatal("expected parsed IPv6")
	}
}
