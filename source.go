package netident

import (
	"net"
	"sync/atomic"
	"time"
)

type urlSource struct {
	url            string
	format         string
	weight         int
	updateInterval time.Duration
	timeout        time.Duration
	providerID     string

	nets       atomic.Pointer[[]*net.IPNet]
	lastUpdate atomic.Int64
}

func (s *urlSource) getNets() []*net.IPNet {
	p := s.nets.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (s *urlSource) setNets(nets []*net.IPNet) {
	s.nets.Store(&nets)
	s.lastUpdate.Store(time.Now().Unix())
}

func (s *urlSource) needUpdate() bool {
	last := s.lastUpdate.Load()
	if last == 0 {
		return true
	}
	return time.Since(time.Unix(last, 0)) >= s.updateInterval
}

type compiledProvider struct {
	id       string
	name     string
	category Category

	stringRules []compiledStringRule
	asnRules    []compiledASNRule
	cidrRules   []compiledCIDRRule
	urlSources  []*urlSource
}
