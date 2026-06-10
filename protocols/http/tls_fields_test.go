//go:build !tinygo
// +build !tinygo

package http

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/tlsx"
)

// TestCertFieldRegistryParity guards the single-source-of-truth invariant:
// every cert data key declared in common.XrayCertFields must be populated by
// tlsx.FillCertDSL. This prevents the converter and the runtime from drifting
// apart when a cert field is added.
func TestCertFieldRegistryParity(t *testing.T) {
	cert := &x509.Certificate{
		Raw:          []byte("test-cert"),
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject:      pkix.Name{CommonName: "test", Organization: []string{"Org"}},
		Issuer:       pkix.Name{CommonName: "issuer"},
	}
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		Version:          0x0303,
		CipherSuite:      0x1301,
	}
	data := make(map[string]interface{})
	tlsx.FillCertDSL(data, state, "example.com")

	for sub, key := range common.XrayCertFields {
		if _, ok := data[key]; !ok {
			t.Errorf("XrayCertFields[%q] -> %q not populated by FillCertDSL", sub, key)
		}
	}
	if _, ok := data[common.RawCertKey]; !ok {
		t.Errorf("RawCertKey %q not populated by FillCertDSL", common.RawCertKey)
	}
}
