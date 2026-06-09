//go:build tinygo
// +build tinygo

package tlsx

import "crypto/tls"

// FingerprintHash mirrors the non-tinygo type so callers compile under tinygo.
type FingerprintHash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// FillCertDSL is a no-op under tinygo, which has no certificate inspection.
func FillCertDSL(data map[string]interface{}, state *tls.ConnectionState, sni string) {}

// NucleiCertFields returns nil under tinygo.
func NucleiCertFields(state *tls.ConnectionState, sni string) map[string]interface{} {
	return nil
}
