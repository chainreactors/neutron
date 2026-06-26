//go:build !tinygo
// +build !tinygo

package http

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/tlsx"
	"github.com/stretchr/testify/require"
)

// TestCertFieldRegistryParity guards the single-source-of-truth invariant:
// every xray cert key declared in common.CertFields must actually be
// populated by the shared tlsx.FillCertDSL path that the HTTP runtime uses.
// This prevents the converter (which decides what cert subfields are evaluable)
// and the runtime (which fills the keys) from drifting apart.
func TestCertFieldRegistryParity(t *testing.T) {
	data := map[string]interface{}{}
	addTLSCertFields(data, newCertTestResponse(t))

	for sub, key := range common.CertFields {
		if _, ok := data[key]; !ok {
			t.Errorf("CertFields[%q] -> %q not populated by addTLSCertFields", sub, key)
		}
	}

	// Guard the xray/nuclei dual-semantics that are easy to break:
	// cert_not_before stays a formatted string (xray timeConvert depends on it),
	// while the nuclei not_before stays a time.Time; serial namespaces differ
	// (xray decimal vs nuclei colon-hex).
	if _, ok := data["cert_not_before"].(string); !ok {
		t.Errorf("cert_not_before must stay a string, got %T", data["cert_not_before"])
	}
	if _, ok := data["not_before"].(time.Time); !ok {
		t.Errorf("nuclei not_before must stay a time.Time, got %T", data["not_before"])
	}
	if data["cert_serial"] != "4660" {
		t.Errorf("cert_serial must be decimal, got %v", data["cert_serial"])
	}
	if data["serial"] != "12:34" {
		t.Errorf("nuclei serial must be colon-hex, got %v", data["serial"])
	}
}

// newCertTestResponse builds an *http.Response whose TLS state carries a leaf
// certificate with known marker fields covering every cert subfield.
func newCertTestResponse(t *testing.T) *http.Response {
	t.Helper()
	leaf := &x509.Certificate{
		Raw:          []byte("der-with-Internet Widgits Pty Ltd-marker"),
		SerialNumber: big.NewInt(0x1234), // decimal 4660 == hex 12:34
		Subject: pkix.Name{
			CommonName:   "hfish.local",
			Organization: []string{"Internet Widgits Pty Ltd"},
		},
		Issuer:    pkix.Name{CommonName: "pa-820", Organization: []string{"qax"}},
		NotBefore: time.Date(2020, 12, 4, 9, 1, 5, 0, time.UTC),
		NotAfter:  time.Date(2120, 12, 4, 9, 1, 5, 0, time.UTC),
		DNSNames:  []string{"ingress-nginx", "hfish.local"},
	}
	return &http.Response{
		TLS: &tls.ConnectionState{
			Version:          0x0303,
			PeerCertificates: []*x509.Certificate{leaf},
		},
	}
}

// TestAddTLSCertFieldsEndToEnd does a real TLS handshake against an httptest
// server and asserts the SAME http response exposes BOTH the xray cert_* keys
// and the nuclei-style keys via the shared tlsx path.
func TestAddTLSCertFieldsEndToEnd(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	// httptest's TLS server uses a cert with Org "Acme Co" and SAN example.com.

	req, err := http.NewRequest("GET", server.URL+"/", nil)
	require.NoError(t, err)
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	data := map[string]interface{}{}
	addTLSCertFields(data, resp)

	// xray namespace.
	require.Contains(t, data["cert_organization"], "Acme")
	require.NotEmpty(t, data["cert_serial"])
	require.IsType(t, "", data["cert_not_before"], "cert_not_before stays a string")
	require.NotEmpty(t, data["raw_cert"])

	// nuclei namespace on the same response.
	require.Contains(t, data["subject_org"], "Acme Co")
	require.Equal(t, "ctls", data["tls_connection"])
	require.NotEmpty(t, data["tls_version"])
	require.IsType(t, time.Time{}, data["not_before"], "nuclei not_before stays a time.Time")
	require.IsType(t, tlsx.FingerprintHash{}, data["fingerprint_hash"])
}
