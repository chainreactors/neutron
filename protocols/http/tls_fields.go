//go:build !tinygo
// +build !tinygo

package http

import "net/http"

func addTLSCertFields(data map[string]interface{}, resp *http.Response) {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return
	}

	cert := resp.TLS.PeerCertificates[0]
	data["cert_subject"] = cert.Subject.String()
	data["cert_issuer"] = cert.Issuer.String()
	data["cert_not_before"] = cert.NotBefore.Format("2006-01-02 03:04:05")
	data["cert_not_after"] = cert.NotAfter.Format("2006-01-02 03:04:05")
}
