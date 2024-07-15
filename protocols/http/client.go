package http

import (
	"crypto/tls"
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
}

var DefaultOption = Configuration{
	5,
	true,
	3,
	false,
	nil,
}

var DefaultTransport = &http.Transport{
	TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS10,
		Renegotiation:      tls.RenegotiateOnceAsClient,
		InsecureSkipVerify: true,
	},
	DialContext: (&net.Dialer{
		Timeout:   time.Duration(DefaultOption.Timeout) * time.Second,
		KeepAlive: time.Duration(DefaultOption.Timeout) * time.Second,
	}).DialContext,
	MaxIdleConnsPerHost: 1,
	IdleConnTimeout:     time.Duration(DefaultOption.Timeout) * time.Second,
	DisableKeepAlives:   false,
	Proxy:               DefaultOption.Proxy,
}

func createClient(opt *Configuration) *http.Client {
	var tr *http.Transport
	if opt.Timeout == DefaultOption.Timeout {
		tr = DefaultTransport
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS10,
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(opt.Timeout) * time.Second,
				KeepAlive: time.Duration(opt.Timeout) * time.Second,
				//DualStack: true,
			}).DialContext,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     time.Duration(opt.Timeout) * time.Second,
			DisableKeepAlives:   false,
			Proxy:               opt.Proxy,
		}
	}

	var jar *cookiejar.Jar
	if opt.CookieReuse {
		jar, _ = cookiejar.New(nil)
	}
	client := &http.Client{
		Transport:     tr,
		Timeout:       time.Duration(opt.Timeout) * time.Second,
		CheckRedirect: makeCheckRedirectFunc(opt.FollowRedirects, 3),
	}
	if jar != nil {
		client.Jar = jar
	}
	return client
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
