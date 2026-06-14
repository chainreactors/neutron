//go:build tinygo
// +build tinygo

package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
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
	client := &http.Client{Transport: &Transport{DialContext: opt.DialContext}}
	if opt.CookieReuse {
		client.Jar = newCookieJar()
	}
	return client
}

func newCookieJar() http.CookieJar {
	return &tinyCookieJar{cookies: make(map[string]*tinyCookie)}
}

// TinyGo targets do not consistently provide net/http/cookiejar, but
// http.Client only needs these CookieJar hooks to carry redirect cookies.
type tinyCookieJar struct {
	mu      sync.Mutex
	cookies map[string]*tinyCookie
}

type tinyCookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HostOnly bool
	Expires  time.Time
	Created  time.Time
}

func (j *tinyCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j == nil || u == nil {
		return
	}

	host := canonicalCookieHost(u)
	if host == "" {
		return
	}

	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()

	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}

		domain, hostOnly, ok := cookieDomain(cookie.Domain, host)
		if !ok {
			continue
		}

		path := cookie.Path
		if !strings.HasPrefix(path, "/") {
			path = defaultCookiePath(u.Path)
		}

		key := tinyCookieKey(domain, path, cookie.Name)
		if cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && !cookie.Expires.After(now)) {
			delete(j.cookies, key)
			continue
		}

		stored := &tinyCookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   domain,
			Path:     path,
			Secure:   cookie.Secure,
			HostOnly: hostOnly,
			Created:  now,
		}
		if cookie.MaxAge > 0 {
			stored.Expires = now.Add(time.Duration(cookie.MaxAge) * time.Second)
		} else if !cookie.Expires.IsZero() {
			stored.Expires = cookie.Expires
		}
		j.cookies[key] = stored
	}
}

func (j *tinyCookieJar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil || u == nil {
		return nil
	}

	host := canonicalCookieHost(u)
	if host == "" {
		return nil
	}
	path := u.Path
	if path == "" {
		path = "/"
	}

	now := time.Now()
	https := strings.EqualFold(u.Scheme, "https")

	j.mu.Lock()
	defer j.mu.Unlock()

	matched := make([]*tinyCookie, 0)
	for key, cookie := range j.cookies {
		if !cookie.Expires.IsZero() && !cookie.Expires.After(now) {
			delete(j.cookies, key)
			continue
		}
		if cookie.Secure && !https {
			continue
		}
		if cookie.HostOnly {
			if host != cookie.Domain {
				continue
			}
		} else if !cookieDomainMatch(host, cookie.Domain) {
			continue
		}
		if !cookiePathMatch(path, cookie.Path) {
			continue
		}
		matched = append(matched, cookie)
	}

	sort.Slice(matched, func(i, j int) bool {
		if len(matched[i].Path) != len(matched[j].Path) {
			return len(matched[i].Path) > len(matched[j].Path)
		}
		if !matched[i].Created.Equal(matched[j].Created) {
			return matched[i].Created.Before(matched[j].Created)
		}
		return matched[i].Name < matched[j].Name
	})

	result := make([]*http.Cookie, 0, len(matched))
	for _, cookie := range matched {
		result = append(result, &http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	return result
}

func canonicalCookieHost(u *url.URL) string {
	host := u.Hostname()
	if host == "" {
		host = u.Host
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func cookieDomain(domain, host string) (string, bool, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return host, true, true
	}

	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", false, false
	}
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false, false
	}
	return domain, false, true
}

func cookieDomainMatch(host, domain string) bool {
	if host == domain {
		return true
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+domain)
}

func defaultCookiePath(path string) string {
	if path == "" || path[0] != '/' {
		return "/"
	}

	index := strings.LastIndex(path, "/")
	if index <= 0 {
		return "/"
	}
	return path[:index]
}

func cookiePathMatch(requestPath, cookiePath string) bool {
	if requestPath == "" {
		requestPath = "/"
	}
	if cookiePath == "" {
		cookiePath = "/"
	}
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	if strings.HasSuffix(cookiePath, "/") {
		return true
	}
	return len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/'
}

func tinyCookieKey(domain, path, name string) string {
	return domain + "\x00" + path + "\x00" + name
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
