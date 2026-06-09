//go:build !tinygo
// +build !tinygo

package http

import (
	"net/http"

	"github.com/chainreactors/neutron/protocols/utils/tlsx"
)

// addTLSCertFields fills certificate-derived keys into the response data map so
// that DSL matchers converted from xray's response.cert.* / response.raw_cert
// (and nuclei's cert/tls keys) can be evaluated natively. The extraction itself
// lives in protocols/utils/tlsx, shared with the SSL protocol so the two paths
// never drift. Only the standard library is used.
func addTLSCertFields(data map[string]interface{}, resp *http.Response) {
	if resp == nil || resp.TLS == nil {
		return
	}
	sni := ""
	if resp.Request != nil && resp.Request.URL != nil {
		sni = resp.Request.URL.Hostname()
	}
	tlsx.FillCertDSL(data, resp.TLS, sni)
}
