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

type RedirectPolicy uint8

const (
	DontFollowRedirect RedirectPolicy = iota
	FollowAllRedirect
	FollowSameHostRedirect
)

type Configuration struct {
	Timeout        int
	RedirectPolicy RedirectPolicy
	MaxRedirects   int
	CookieReuse    bool
	DisableCookie  bool
	Proxy          func(*http.Request) (*url.URL, error)
	DialContext    func(ctx context.Context, network, address string) (net.Conn, error)
}

var DefaultOption = Configuration{
	Timeout:        5,
	RedirectPolicy: FollowAllRedirect,
	MaxRedirects:   3,
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

// newCookieJar returns nil under TinyGo. The primary TinyGo target is
// WASM where the browser handles cookies and redirects via fetch();
// Go-level CookieJar is never effectively used.
func newCookieJar() http.CookieJar {
	return nil
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
