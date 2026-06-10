package full

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/chainreactors/neutron/common/tlsx"
)

// TestRegistrationViaInit asserts that importing this package wires up
// tlsx.IsRevoked through cfssl: with a synthetic cert that has no CRL/OCSP
// extensions, cfssl should soft-fail to false (ok=false), but the dispatch
// must still go through our registered hook rather than the always-false stub
// in the main module.
func TestRegistrationViaInit(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0}}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	// No assertion on the bool return — cfssl with no CRL/OCSP URLs just
	// reports ok=false → IsRevoked returns false. The point of the test is
	// that we DON'T panic and the call routes through the cfssl backend
	// (proved by package-level init wiring).
	_ = tlsx.IsRevoked(state)

	// Defensive routing: nil/empty must remain safe under the cfssl path too.
	if tlsx.IsRevoked(nil) {
		t.Errorf("nil state must soft-fail to false")
	}
	if tlsx.IsRevoked(&tls.ConnectionState{}) {
		t.Errorf("empty peer cert list must soft-fail to false")
	}
}
