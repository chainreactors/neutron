//go:build !tinygo
// +build !tinygo

package tlsx

import (
	"crypto/tls"
	"strings"
	"time"

	"github.com/chainreactors/neutron/common"
)

// FillCertDSL populates both xray-style cert_* keys and nuclei-style native
// keys into data from the TLS connection state. sni is used for mismatch
// detection; pass "" to skip mismatch/sni fields.
func FillCertDSL(data map[string]interface{}, state *tls.ConnectionState, sni string) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return
	}

	leaf := state.PeerCertificates[0]
	certNames := CertificateNames(leaf)
	serial := FormatSerial(leaf)
	fingerprint := CertificateFingerprintHash{
		MD5:    CertFingerprint(leaf, "md5"),
		SHA1:   CertFingerprint(leaf, "sha1"),
		SHA256: CertFingerprint(leaf, "sha256"),
	}

	expired := time.Now().After(leaf.NotAfter)

	// nuclei-style keys
	data["subject_cn"] = leaf.Subject.CommonName
	data["subject_an"] = leaf.DNSNames
	data["domains"] = UniqueDomains(certNames)
	data["subject_dn"] = leaf.Subject.String()
	data["subject_org"] = leaf.Subject.Organization
	data["issuer_cn"] = leaf.Issuer.CommonName
	data["issuer_dn"] = leaf.Issuer.String()
	data["issuer_org"] = leaf.Issuer.Organization
	data["emails"] = leaf.EmailAddresses
	data["serial"] = serial
	data["not_before"] = leaf.NotBefore
	data["not_after"] = leaf.NotAfter
	data["tls_version"] = TLSVersionName(state.Version)
	data["cipher"] = CipherName(state.CipherSuite)
	data["fingerprint_hash"] = fingerprint
	data["wildcard_certificate"] = IsWildcardName(certNames)
	data["self_signed"] = IsSelfSigned(leaf)
	data["expired"] = expired

	if sni != "" {
		data["sni"] = sni
		data["mismatched"] = IsMismatchedCert(sni, certNames)
	}

	// xray-style cert_* keys
	data["cert_subject"] = leaf.Subject.String()
	data["cert_issuer"] = leaf.Issuer.String()
	data["cert_not_before"] = leaf.NotBefore.Format("2006-01-02 03:04:05")
	data["cert_not_after"] = leaf.NotAfter.Format("2006-01-02 03:04:05")
	data["cert_dnsnames"] = strings.Join(leaf.DNSNames, " ")
	data["cert_serial"] = leaf.SerialNumber.String()
	data["cert_common_name"] = leaf.Subject.CommonName
	data["cert_organization"] = strings.Join(leaf.Subject.Organization, " ")

	// raw_cert: concatenated DER bytes of the whole presented chain
	var raw strings.Builder
	for _, cert := range state.PeerCertificates {
		raw.Write(cert.Raw)
	}
	if raw.Len() > 0 {
		data[common.RawCertKey] = raw.String()
	}
}
