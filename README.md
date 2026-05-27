# netident

Identify network providers, search engine bots, and cloud platforms by matching IP, PTR, WHOIS, and ASN data against a weighted JSON rule database.

## Install

Library:

```bash
go get github.com/aredoff/netident
```

CLI — download a binary from [GitHub Releases](https://github.com/aredoff/netident/releases).

## CLI

Identify a provider by IP, PTR, WHOIS, or ASN data:

```bash
netident -ip 66.249.79.1 -ptr crawl-66-249-79-1.googlebot.com
```

Output:

```text
provider=googlebot name="Google Bot" category=bot score=1000
  ptr "*.googlebot.com" weight=1000
```

More examples:

```bash
netident -ip 8.8.8.8 -netname GOOGLE-CLOUD
netident -asn 15169 -asn-name GOOGLE
netident -netmail abuse@amazonaws.com -ptr ec2-1-2-3-4.compute.amazonaws.com
netident -version
netident -validate ./providers.json
```

Validate a custom config:

```bash
netident -validate ./my-providers.json
```

Output:

```text
config ok: ./my-providers.json
```

Flags:

| Flag | Description |
|---|---|
| `-ip` | IP address |
| `-ptr` | PTR record |
| `-netname` | WHOIS netname |
| `-netmail` | WHOIS netmail |
| `-asn` | ASN number |
| `-asn-name` | ASN organization name |
| `-asn-mail` | ASN abuse email |
| `-validate` | Validate `providers.json`, load config, and run a probe identify |
| `-config` | Path to custom `providers.json` (default: embedded production config) |
| `-cache-dir` | Directory for network URL cache |
| `-version` | Print version and exit |

At least one input flag is required for identify mode. `-validate` runs standalone and does not require input flags.

## Library usage

```go
package main

import (
    "context"
    "net"

    "github.com/aredoff/netident"
)

func main() {
    det, err := netident.New()
    if err != nil {
        panic(err)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    if err := det.Start(ctx); err != nil {
        panic(err)
    }
    defer det.Close()

    result := det.Identify(netident.Input{
        IP:  net.ParseIP("66.249.79.1"),
        PTR: "crawl-66-249-79-1.googlebot.com",
    })

    if result.OK && result.Category == netident.CategoryBot {
        // never block bots
        return
    }
}
```

## Lifecycle

| Method | Description |
|---|---|
| `New*` | Load JSON config, compile rules, read cache. No goroutines. |
| `Start(ctx)` | Start background network URL updater. |
| `Close()` | Stop updater and wait for shutdown. |
| `Identify` | Match input against all providers, return best result. |

`Identify` works immediately after `New` using static rules and cached CIDR lists.

## Config format

Each provider has weighted rules:

```json
{
  "version": 1,
  "defaults": {"min_score": 1, "rule_weight": 10},
  "providers": [
    {
      "id": "googlebot",
      "name": "Google Bot",
      "category": "bot",
      "rules": {
        "ptr": [{"match": "*.googlebot.com", "weight": 1000}],
        "network_urls": [{
          "url": "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
          "format": "google_prefixes",
          "weight": 900
        }]
      }
    }
  ]
}
```

All rules use `{"match": "...", "weight": N}`. Omitted `weight` defaults to `defaults.rule_weight`.

Supported rule fields: `ptr`, `networks`, `network_urls`, `netname`, `netmail`, `asn`, `asn_name`, `asn_mail`.

Categories: `bot`, `cloud`, `cdn`, `hosting`, `isp`, `other`.

## License

MIT
