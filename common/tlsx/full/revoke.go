// Package full registers a cfssl-based CRL/OCSP revocation backend into tlsx.
// Import as: _ "github.com/chainreactors/neutron/common/tlsx/full"
package full

import (
	"crypto/tls"
	"net/http"
	"time"

	cflog "github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"

	"github.com/chainreactors/neutron/common/tlsx"
)

func init() {
	revoke.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	cflog.Level = cflog.LevelError
	tlsx.RegisterRevokeCheck(checkRevoked)
}

func checkRevoked(state *tls.ConnectionState) bool {
	if state == nil || len(state.PeerCertificates) == 0 {
		return false
	}
	revoked, ok := revoke.VerifyCertificate(state.PeerCertificates[0])
	if !ok {
		return false
	}
	return revoked
}
