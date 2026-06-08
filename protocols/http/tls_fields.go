//go:build !tinygo
// +build !tinygo

package http

import (
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/chainreactors/neutron/common"
)

// certExtractors maps a neutron data-map key to a function that derives its
// string value from the leaf certificate. Keys must stay in sync with the
// values of common.XrayCertFields (asserted by TestCertFieldRegistryParity).
var certExtractors = map[string]func(*x509.Certificate) string{
	"cert_subject":      func(c *x509.Certificate) string { return c.Subject.String() },
	"cert_issuer":       func(c *x509.Certificate) string { return c.Issuer.String() },
	"cert_not_before":   func(c *x509.Certificate) string { return c.NotBefore.Format("2006-01-02 03:04:05") },
	"cert_not_after":    func(c *x509.Certificate) string { return c.NotAfter.Format("2006-01-02 03:04:05") },
	"cert_dnsnames":     func(c *x509.Certificate) string { return strings.Join(c.DNSNames, " ") },
	"cert_serial":       func(c *x509.Certificate) string { return c.SerialNumber.String() },
	"cert_common_name":  func(c *x509.Certificate) string { return c.Subject.CommonName },
	"cert_organization": func(c *x509.Certificate) string { return strings.Join(c.Subject.Organization, " ") },
}

// addTLSCertFields fills certificate-derived keys into the response data map so
// that DSL matchers converted from xray's response.cert.* / response.raw_cert
// can be evaluated natively. Only the standard library is used.
func addTLSCertFields(data map[string]interface{}, resp *http.Response) {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return
	}

	leaf := resp.TLS.PeerCertificates[0]
	for key, extract := range certExtractors {
		if v := extract(leaf); v != "" {
			data[key] = v
		}
	}

	// raw_cert: concatenate the DER bytes of the whole presented chain. This
	// mirrors xray's bcontains-over-DER semantics — organization/CN strings are
	// stored as literal ASCII inside the DER encoding.
	var raw strings.Builder
	for _, cert := range resp.TLS.PeerCertificates {
		raw.Write(cert.Raw)
	}
	if raw.Len() > 0 {
		data[common.RawCertKey] = raw.String()
	}
}
