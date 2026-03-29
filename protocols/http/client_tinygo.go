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
}

var DefaultOption = Configuration{
	5,
	true,
	3,
	false,
	nil,
}

type Transport struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(req)
}

var DefaultTransport = &Transport{}

func createClient(opt *Configuration) *http.Client {
	client := &http.Client{
		Transport: DefaultTransport,
	}
	if opt != nil && opt.Timeout > 0 {
		// TinyGo's net/http client still supports the high-level timeout field.
		// Keep the transport intentionally minimal and ignore cookie jar reuse.
	}
	return client
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
