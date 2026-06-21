//go:build tinygo
// +build tinygo

package protocols

import "net/http"

// defaultScanCookieJar returns nil under TinyGo. The primary TinyGo target is
// WASM where the browser handles cookies (and redirects) via fetch(); a
// Go-level CookieJar is never effectively used.
func defaultScanCookieJar() http.CookieJar {
	return nil
}
