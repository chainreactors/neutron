//go:build !tinygo
// +build !tinygo

package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/neutron/common"
)

func sampleState() *tls.ConnectionState {
	leaf := &x509.Certificate{
		Raw:            []byte("der-bytes-Internet Widgits Pty Ltd-marker"),
		SerialNumber:   big.NewInt(0x1234), // decimal 4660 == hex 12:34
		DNSNames:       []string{"ingress-nginx", "leaf.example"},
		EmailAddresses: []string{"admin@example.com"},
		NotBefore:      time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:       time.Date(2120, 1, 2, 3, 4, 5, 0, time.UTC),
		Subject: pkix.Name{
			CommonName:   "leaf.example",
			Organization: []string{"Internet Widgits Pty Ltd"},
		},
		Issuer: pkix.Name{CommonName: "issuer-cn", Organization: []string{"qax"}},
	}
	return &tls.ConnectionState{
		Version:          0x0303, // tls12
		CipherSuite:      0x1301, // TLS_AES_128_GCM_SHA256
		ServerName:       "leaf.example",
		PeerCertificates: []*x509.Certificate{leaf},
	}
}

func TestFillCertDSLDualNamespaces(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "leaf.example")

	// xray namespace: exact for stable fields, substring for DN strings whose
	// component ordering is not contractually fixed.
	exact := map[string]string{
		"cert_not_before":   "2020-01-02 03:04:05",
		"cert_dnsnames":     "ingress-nginx leaf.example",
		"cert_serial":       "4660", // decimal
		"cert_common_name":  "leaf.example",
		"cert_organization": "Internet Widgits Pty Ltd",
	}
	for k, want := range exact {
		got, ok := data[k].(string)
		if !ok || got != want {
			t.Errorf("%s = %v, want %q", k, data[k], want)
		}
	}
	if s, _ := data["cert_subject"].(string); !strings.Contains(s, "Internet Widgits Pty Ltd") {
		t.Errorf("cert_subject missing org: %q", s)
	}
	if s, _ := data["cert_issuer"].(string); !strings.Contains(s, "issuer-cn") {
		t.Errorf("cert_issuer missing CN: %q", s)
	}

	// nuclei namespace (typed).
	if _, ok := data["not_before"].(time.Time); !ok {
		t.Errorf("nuclei not_before must be time.Time, got %T", data["not_before"])
	}
	if data["serial"] != "12:34" {
		t.Errorf("nuclei serial = %v, want colon-hex 12:34", data["serial"])
	}
	if data["tls_version"] != "tls12" {
		t.Errorf("tls_version = %v, want tls12", data["tls_version"])
	}
	if data["cipher"] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher = %v", data["cipher"])
	}
	if data["mismatched"] != false {
		t.Errorf("mismatched should be false for matching SNI, got %v", data["mismatched"])
	}
	if data["expired"] != false {
		t.Errorf("expired should be false for far-future not_after, got %v", data["expired"])
	}
	fp, ok := data["fingerprint_hash"].(FingerprintHash)
	if !ok || len(fp.SHA256) != 64 || len(fp.SHA1) != 40 || len(fp.MD5) != 32 {
		t.Errorf("fingerprint_hash shape wrong: %#v", data["fingerprint_hash"])
	}

	// raw_cert carries the DER marker for xray bcontains-style matching.
	raw, ok := data[common.RawCertKey].(string)
	if !ok || !strings.Contains(raw, "Internet Widgits Pty Ltd") {
		t.Errorf("raw_cert missing DER marker: %q", raw)
	}
}

func TestFillCertDSLNoCert(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, nil, "")
	if len(data) != 0 {
		t.Errorf("expected no keys for nil state, got %v", data)
	}
	FillCertDSL(data, &tls.ConnectionState{}, "")
	if len(data) != 0 {
		t.Errorf("expected no keys for empty chain, got %v", data)
	}
}

func TestFillCertDSLEmptySNINoMismatch(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "") // empty SNI must not flag mismatch
	if data["mismatched"] != false {
		t.Errorf("empty SNI should not be marked mismatched, got %v", data["mismatched"])
	}
}

func TestUntrustedSelfSignedFromSample(t *testing.T) {
	// sampleState() is a synthetic self-signed leaf with random DER. It must
	// fail x509.Verify against the system root pool — that's the whole point
	// of the untrusted flag: anything a normal HTTPS client would reject.
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "leaf.example")
	if data["untrusted"] != true {
		t.Errorf("synthetic self-signed leaf should be untrusted=true, got %v", data["untrusted"])
	}
}

func TestUntrustedNoState(t *testing.T) {
	// Defensive: nil/empty state must not crash and must report false.
	if IsUntrusted(nil, "x") {
		t.Errorf("nil state should not be untrusted")
	}
	if IsUntrusted(&tls.ConnectionState{}, "x") {
		t.Errorf("empty peer cert list should not be untrusted")
	}
}

func TestRevokedNoState(t *testing.T) {
	// Defensive: same shape as untrusted — no peer certs means we have nothing
	// to check, so report not-revoked (soft-fail by design).
	if IsRevoked(nil) {
		t.Errorf("nil state should not be revoked")
	}
	if IsRevoked(&tls.ConnectionState{}) {
		t.Errorf("empty peer cert list should not be revoked")
	}
}

func TestRevokedKeyPresent(t *testing.T) {
	data := map[string]interface{}{}
	FillCertDSL(data, sampleState(), "leaf.example")
	_, ok := data["revoked"].(bool)
	if !ok {
		t.Fatalf("revoked must be bool, got %T (%v)", data["revoked"], data["revoked"])
	}
}

func TestIsRevokedSoftFail(t *testing.T) {
	if IsRevoked(nil) {
		t.Errorf("nil state must soft-fail to false")
	}
	if IsRevoked(&tls.ConnectionState{}) {
		t.Errorf("empty peer cert list must soft-fail to false")
	}
}

// TestCipherNameWeakSuites locks in the cipher-naming fix: weak RC4/3DES suites
// that tls.InsecureCipherSuites() can negotiate must render as their real IANA
// name (so nuclei's insecure-cipher-suite-detect can match `part: cipher`), and
// an unknown id must still fall back to the bare "0x%04x" hex form -- NOT to
// tls.CipherSuiteName -- keeping this package go1.11-safe.
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
