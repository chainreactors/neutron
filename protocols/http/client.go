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
	"strings"
	"time"

	"github.com/chainreactors/neutron/protocols"
)

func init() {
	protocols.CookieJarFactory = func() http.CookieJar {
		jar, _ := cookiejar.New(nil)
		return jar
	}
}

var ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;"

// RedirectPolicy controls how the HTTP client follows redirects, mirroring
// nuclei's RedirectFlow semantics.
type RedirectPolicy uint8

const (
	DontFollowRedirect       RedirectPolicy = iota // default — return 3xx as-is
	FollowAllRedirect                              // follow all redirects
	FollowSameHostRedirect                         // follow only when host matches the initial request
)

type Configuration struct {
	Timeout        int
	RedirectPolicy RedirectPolicy
	MaxRedirects   int
	CookieReuse    bool
	Proxy          func(*http.Request) (*url.URL, error)
	DialContext    func(ctx context.Context, network, address string) (net.Conn, error)
}

var DefaultOption = Configuration{
	Timeout:        5,
	RedirectPolicy: FollowAllRedirect,
	MaxRedirects:   3,
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
		CheckRedirect: makeCheckRedirectFunc(opt.RedirectPolicy, opt.MaxRedirects),
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

func makeCheckRedirectFunc(policy RedirectPolicy, maxRedirects int) checkRedirectFunc {
	return func(req *http.Request, via []*http.Request) error {
		if policy == DontFollowRedirect {
			return http.ErrUseLastResponse
		}

		if policy == FollowSameHostRedirect && len(via) > 0 {
			newHost := normalizeHost(req.URL)
			var oldHost string
			if via[0].Host != "" {
				oldHost = normalizeHost(&url.URL{Scheme: via[0].URL.Scheme, Host: via[0].Host})
			} else {
				oldHost = normalizeHost(via[0].URL)
			}
			if newHost != oldHost {
				return http.ErrUseLastResponse
			}
		}

		limit := maxRedirects
		if limit == 0 {
			limit = defaultMaxRedirects
		}
		if len(via) > limit {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func normalizeHost(u *url.URL) string {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return strings.ToLower(u.Host)
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		if strings.Contains(host, ":") {
			return "[" + strings.ToLower(host) + "]"
		}
		return strings.ToLower(host)
	}
	return strings.ToLower(u.Host)
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
