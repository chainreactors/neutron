//go:build !tinygo
// +build !tinygo

package tlsx

import (
	"crypto/tls"
	"testing"
)

// TestCipherNameWeakSuites locks in the cipher-naming fix: weak RC4/3DES suites
// that tls.InsecureCipherSuites() can negotiate must render as their real IANA
// name (so nuclei's insecure-cipher-suite-detect can match `part: cipher`), and
// an unknown id must still fall back to the bare "0x%04x" hex form — NOT to
// tls.CipherSuiteName — keeping this package go1.11-safe.
func TestCipherNameWeakSuites(t *testing.T) {
	cases := []struct {
		id   uint16
		want string
	}{
		// weak suites added to the map
		{tls.TLS_RSA_WITH_RC4_128_SHA, "TLS_RSA_WITH_RC4_128_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
		{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
		{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
		// modern suite still correct
		{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		// TLS 1.3 literal id
		{0x1301, "TLS_AES_128_GCM_SHA256"},
	}
	for _, c := range cases {
		if got := CipherName(c.id); got != c.want {
			t.Errorf("CipherName(0x%04x) = %q, want %q", c.id, got, c.want)
		}
	}

	// Unknown id must be bare hex (proves fallback is NOT tls.CipherSuiteName,
	// which would return e.g. a real name or differ in format).
	if got := CipherName(0x9999); got != "0x9999" {
		t.Errorf("CipherName(unknown) = %q, want bare hex %q", got, "0x9999")
	}
}
