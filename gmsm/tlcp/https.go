package tlcp

import (
	"context"
	"net"
	"net/http"
	"time"
)

type HttpTransportOptions struct {
	Dialer                 *net.Dialer
	TLSHandshakeTimeout    time.Duration
	DisableKeepAlives      bool
	DisableCompression     bool
	MaxIdleConns           int
	MaxIdleConnsPerHost    int
	MaxConnsPerHost        int
	IdleConnTimeout        time.Duration
	ResponseHeaderTimeout  time.Duration
	ExpectContinueTimeout  time.Duration
	MaxResponseHeaderBytes int64
	WriteBufferSize        int
	ReadBufferSize         int
	ForceAttemptHTTP2      bool
}

var DefaultHttpTransportOptions = &HttpTransportOptions{
	Dialer: &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 60 * time.Second,
	},
	TLSHandshakeTimeout:    30 * time.Second,
	DisableKeepAlives:      false,
	DisableCompression:     false,
	MaxIdleConns:           0,
	MaxIdleConnsPerHost:    0,
	MaxConnsPerHost:        0,
	IdleConnTimeout:        30 * time.Second,
	ResponseHeaderTimeout:  0,
	ExpectContinueTimeout:  0,
	MaxResponseHeaderBytes: 0,
	WriteBufferSize:        0,
	ReadBufferSize:         0,
	ForceAttemptHTTP2:      false,
}

func NewHttpTransport(config *Config, options *HttpTransportOptions) *http.Transport {
	if options == nil {
		options = DefaultHttpTransportOptions
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := Dialer{NetDialer: options.Dialer, Config: config}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:    options.TLSHandshakeTimeout,
		DisableKeepAlives:      options.DisableKeepAlives,
		DisableCompression:     options.DisableCompression,
		MaxIdleConns:           options.MaxIdleConns,
		MaxIdleConnsPerHost:    options.MaxIdleConnsPerHost,
		MaxConnsPerHost:        options.MaxConnsPerHost,
		IdleConnTimeout:        options.IdleConnTimeout,
		ResponseHeaderTimeout:  options.ResponseHeaderTimeout,
		ExpectContinueTimeout:  options.ExpectContinueTimeout,
		MaxResponseHeaderBytes: options.MaxResponseHeaderBytes,
		WriteBufferSize:        options.WriteBufferSize,
		ReadBufferSize:         options.ReadBufferSize,
		ForceAttemptHTTP2:      options.ForceAttemptHTTP2,
	}
}
