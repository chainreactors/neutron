//go:build !tinygo
// +build !tinygo

package http

import (
	"net/http"

	"github.com/chainreactors/neutron/common/tlsx"
)

func addTLSCertFields(data map[string]interface{}, resp *http.Response) {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return
	}
	tlsx.FillCertDSL(data, resp.TLS, "")
}
