package http

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/chainreactors/neutron/protocols"
)

const (
	KeyTransport = "http.transport"
	KeyCookieJar = "http.cookiejar"
	KeyClient    = "http.client"
	KeyProxy     = "http.proxy"
)

func SetTransport(ctx *protocols.ScanContext, t http.RoundTripper) {
	ctx.Set(KeyTransport, t)
}

func GetTransport(ctx *protocols.ScanContext) http.RoundTripper {
	v, ok := ctx.Get(KeyTransport)
	if !ok {
		return nil
	}
	t, _ := v.(http.RoundTripper)
	return t
}

func SetCookieJar(ctx *protocols.ScanContext, j http.CookieJar) {
	ctx.Set(KeyCookieJar, j)
}

func GetCookieJar(ctx *protocols.ScanContext) http.CookieJar {
	v, ok := ctx.Get(KeyCookieJar)
	if !ok {
		return nil
	}
	j, _ := v.(http.CookieJar)
	return j
}

func SetClient(ctx *protocols.ScanContext, c *http.Client) {
	ctx.Set(KeyClient, c)
}

func GetClient(ctx *protocols.ScanContext) *http.Client {
	v, ok := ctx.Get(KeyClient)
	if !ok {
		return nil
	}
	c, _ := v.(*http.Client)
	return c
}

func SetProxy(ctx *protocols.ScanContext, p func(*http.Request) (*url.URL, error)) {
	ctx.Set(KeyProxy, p)
}

func GetProxy(ctx *protocols.ScanContext) func(*http.Request) (*url.URL, error) {
	v, ok := ctx.Get(KeyProxy)
	if !ok {
		return nil
	}
	p, _ := v.(func(*http.Request) (*url.URL, error))
	return p
}

func NewHTTPScanContext(input string, payloads map[string]interface{}) *protocols.ScanContext {
	ctx := protocols.NewScanContext(input, payloads)
	jar, _ := cookiejar.New(nil)
	SetCookieJar(ctx, jar)
	return ctx
}
