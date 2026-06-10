// Package full plugs a CRL/OCSP revocation backend into the main tlsx package
// via tlsx.RegisterRevokeCheck. It exists as a separate Go module so the
// cloudflare/cfssl dependency closure (and its 4000+ transitive entries in
// go.sum) is paid only by binaries that explicitly opt in.
//
// Usage from a consumer binary:
//
//	import _ "github.com/chainreactors/neutron/common/tlsx/full"
//
// With this import the package's init() registers a checker built on
// cloudflare/cfssl/revoke — the exact backend projectdiscovery/tlsx and
// nuclei use, so revoked-cert templates behave the same as upstream. Without
// the import, tlsx.IsRevoked stays in soft-fail mode (always returns false)
// and the main neutron module remains a go 1.11, stdlib-only build.
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
	// cfssl's revoke package defaults to http.DefaultClient with NO timeout —
	// a single unreachable CRL/OCSP responder would otherwise stall the whole
	// scan. 5s matches nuclei/tlsx's own override. Soft-fail (HardFail=false)
	// is cfssl's default and what we want: a network hiccup shouldn't make us
	// flag a healthy cert as revoked.
	revoke.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	// cfssl logs every revocation check at INFO level to stderr by default,
	// which floods scanner output. Raise the level to Error so only real
	// problems surface — the revoked/ok return values carry the data we
	// actually consume.
	cflog.Level = cflog.LevelError

	tlsx.RegisterRevokeCheck(checkRevoked)
}

// checkRevoked routes a TLS connection state through cfssl's CRL/OCSP backend.
// We deliberately mirror tlsx upstream behavior: when cfssl's check could not
// complete (ok=false from VerifyCertificate), we report false rather than
// surface the network failure as a positive "REVOKED" — false positives here
// are far noisier than the small miss rate from soft-fail.
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
