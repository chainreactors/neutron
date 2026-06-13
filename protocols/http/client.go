//go:build !tinygo
// +build !tinygo

package http

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

var ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;"

type Configuration struct {
	Timeout         int
	FollowRedirects bool
	MaxRedirects    int
	CookieReuse     bool
	Proxy           func(*http.Request) (*url.URL, error)
	// DialContext 非 nil 时作为该 client 专属 transport 的 DialContext（可为代理）。
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

var DefaultOption = Configuration{
	Timeout:         5,
	FollowRedirects: true,
	MaxRedirects:    3,
}

// DefaultTransport 仅作为不可变的默认配置参考保留；createClient 不再共享它，
// 而是每次构造一个全新的 transport，避免并发下多个模板/执行相互污染。
var DefaultTransport = newTransport(nil)

func newTransport(dialContext func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     3 * time.Second,
		DisableKeepAlives:   false,
	}
	if dialContext != nil {
		tr.DialContext = dialContext
	} else {
		tr.DialContext = (&net.Dialer{KeepAlive: 3 * time.Second}).DialContext
	}
	return tr
}

func createClient(opt *Configuration) *http.Client {
	// 每个 client 使用独立 transport（克隆默认配置 + 注入可选 DialContext/Proxy），
	// 不共享全局 DefaultTransport，杜绝跨执行的代理/连接泄漏。
	tr := newTransport(opt.DialContext)
	if opt.Proxy != nil {
		tr.Proxy = opt.Proxy
	}

	var jar *cookiejar.Jar
	if opt.CookieReuse {
		jar = newCookieJar()
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: makeCheckRedirectFunc(opt.FollowRedirects, opt.MaxRedirects),
	}
	if jar != nil {
		client.Jar = jar
	}
	return client
}

func newCookieJar() *cookiejar.Jar {
	jar, _ := cookiejar.New(nil)
	return jar
}

const defaultMaxRedirects = 10

type checkRedirectFunc func(req *http.Request, via []*http.Request) error

func makeCheckRedirectFunc(followRedirects bool, maxRedirects int) checkRedirectFunc {
	return func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		if maxRedirects == 0 {
			if len(via) > defaultMaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}

		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
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
