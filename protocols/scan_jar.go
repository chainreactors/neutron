//go:build !tinygo
// +build !tinygo

package protocols

import (
	"net/http"
	"net/http/cookiejar"
)

// defaultScanCookieJar returns a fresh, empty cookie jar for one scan
// execution, matching nuclei's contextargs pattern: cookies are shared within a
// scan (so redirect chains carry Set-Cookie) and isolated across scans.
//
// Under the standard build this constructs a real net/http/cookiejar. The
// TinyGo variant (scan_jar_tinygo.go) returns nil because the primary TinyGo
// target is WASM, where the browser handles cookies via fetch().
func defaultScanCookieJar() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	return jar
}
