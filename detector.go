package netident

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

type NetworkCache interface {
	Load(key string) (data []byte, updated time.Time, err error)
	Store(key string, data []byte) error
}

type options struct {
	httpClient *http.Client
	logger     *slog.Logger
	cache      NetworkCache
	configData []byte
}

type Option func(*options)

func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		o.httpClient = c
	}
}

func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

func WithCache(c NetworkCache) Option {
	return func(o *options) {
		o.cache = c
	}
}

func WithCacheDir(dir string) Option {
	return func(o *options) {
		o.cache = NewFileCache(dir)
	}
}

func defaultOptions() options {
	return options{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     slog.Default(),
	}
}

func applyOptions(opts []Option) options {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

type Detector struct {
	minScore   int
	providers  []*compiledProvider
	httpClient *http.Client
	logger     *slog.Logger
	cache      NetworkCache
	sources    []*urlSource

	started bool
	stopCh  chan struct{}
	doneCh  chan struct{}
	upCtx   context.Context
}
