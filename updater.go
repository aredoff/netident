package netident

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const updaterTickInterval = 5 * time.Minute

var (
	errAlreadyStarted = errors.New("netident: already started")
)

func (d *Detector) Start(ctx context.Context) error {
	if d.started {
		return errAlreadyStarted
	}
	d.started = true
	d.upCtx = ctx
	d.stopCh = make(chan struct{})
	d.doneCh = make(chan struct{})

	d.fetchStaleSources()

	go d.runUpdater(ctx)
	return nil
}

func (d *Detector) Close() error {
	if !d.started {
		return nil
	}
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
	if d.doneCh != nil {
		<-d.doneCh
	}
	d.started = false
	return nil
}

func (d *Detector) Ready(ctx context.Context) error {
	if len(d.sources) == 0 {
		return nil
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	for time.Now().Before(deadline) {
		allReady := true
		for _, s := range d.sources {
			if len(s.getNets()) == 0 {
				allReady = false
				break
			}
		}
		if allReady {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("netident: ready timeout")
}

func (d *Detector) runUpdater(ctx context.Context) {
	defer close(d.doneCh)

	ticker := time.NewTicker(updaterTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.fetchStaleSources()
		}
	}
}

func (d *Detector) fetchStaleSources() {
	var wg sync.WaitGroup
	for _, s := range d.sources {
		if !s.needUpdate() {
			continue
		}
		wg.Add(1)
		go func(src *urlSource) {
			defer wg.Done()
			if err := d.fetchSource(src); err != nil {
				d.logger.Error("fetch network source failed", "url", src.url, "error", err)
			}
		}(s)
	}
	wg.Wait()
}

func (d *Detector) fetchSource(s *urlSource) error {
	ctx, cancel := context.WithTimeout(d.upCtx, s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	nets, err := parseURLBody(s.format, bytes.NewReader(body))
	if err != nil {
		return err
	}

	s.setNets(nets)

	if d.cache != nil {
		data, err := marshalNets(nets)
		if err != nil {
			return err
		}
		if err := d.cache.Store(s.url, data); err != nil {
			d.logger.Error("cache store failed", "url", s.url, "error", err)
		}
	}

	d.logger.Debug("network source updated", "url", s.url, "prefixes", len(nets))
	return nil
}
