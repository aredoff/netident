package netident

import "net"

type Input struct {
	IP      net.IP
	PTR     string
	Netname string
	Netmail string
	ASN     *int
	ASNName string
	ASNMail string
}
