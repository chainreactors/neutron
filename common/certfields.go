package common

// XrayCertFields maps an xray `response.cert.<sub>` subfield name to the
// neutron data-map key that the HTTP response populates. This is the single
// source of truth shared by the converter (which decides what subfields are
// evaluable) and the HTTP runtime (which fills the keys). Adding a cert field
// means adding one entry here plus its extractor in protocols/http.
//
// Aliases (e.g. cn -> common_name) may point at the same data key.
var XrayCertFields = map[string]string{
	"subject":      "cert_subject",
	"issuer":       "cert_issuer",
	"not_before":   "cert_not_before",
	"not_after":    "cert_not_after",
	"dnsnames":     "cert_dnsnames",
	"serial":       "cert_serial",
	"common_name":  "cert_common_name",
	"cn":           "cert_common_name",
	"organization": "cert_organization",
	"org":          "cert_organization",
}

// RawCertKey is the data-map key holding the concatenated raw DER bytes of the
// peer certificate chain. xray's `response.raw_cert.bcontains(...)` matches
// against this (printable strings in DER are stored as literal ASCII).
const RawCertKey = "raw_cert"
