//go:build tinygo
// +build tinygo

package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
)

var ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;"

type Configuration struct {
	Timeout         int
	FollowRedirects bool
	MaxRedirects    int
	CookieReuse     bool
	Proxy           func(*http.Request) (*url.URL, error)
	DialContext     func(ctx context.Context, network, address string) (net.Conn, error)
}

var DefaultOption = Configuration{
	Timeout:         5,
	FollowRedirects: true,
	MaxRedirects:    3,
}

type Transport struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(req)
}

var DefaultTransport = &Transport{}

func createClient(opt *Configuration) *http.Client {
	return &http.Client{Transport: &Transport{DialContext: opt.DialContext}}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func NopCloser(r io.Reader) io.ReadCloser {
	return struct {
		io.Reader
		io.Closer
	}{
		Reader: r,
		Closer: nopCloser{},
	}
}
