//go:build !tinygo
// +build !tinygo

// Package tlsx is the single, standard-library-only place that turns a TLS
// handshake's leaf certificate and connection state into neutron DSL keys.
//
// It deliberately exposes TWO key namespaces from the same certificate so that
// both template dialects work against the same response:
//
//   - xray style  (cert_subject, cert_issuer, cert_not_before, ...): string
//     values, populated to mirror xray's response.cert.* semantics. These are
//     what the xray→neutron converter emits.
//   - nuclei style (subject_cn, issuer_dn, tls_version, cipher, fingerprint_hash,
//     not_before, ...): richer typed values mirroring nuclei's `ssl` protocol.
//
// Both the HTTP runtime (protocols/http) and the SSL protocol (protocols/ssl)
// call FillCertDSL so the two paths never drift apart again.
package tlsx

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/chainreactors/neutron/common"
)

const xrayTimeLayout = "2006-01-02 03:04:05"

// FingerprintHash holds the leaf certificate fingerprints in the shape nuclei's
// ssl protocol exposes (a structured object, not flattened keys).
type FingerprintHash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// FillCertDSL populates `data` with both the xray-style cert_* keys and the
// nuclei-style certificate/handshake keys derived from the leaf certificate in
// `state`. `sni` is the server name used for the mismatch check (the HTTP path
// passes the request hostname; the SSL path passes its resolved SNI).
//
// It is a no-op when there is no certificate. Connection-level metadata
// (host/port/matched/ip/response/type) is intentionally left to the caller.
func FillCertDSL(data map[string]interface{}, state *tls.ConnectionState, sni string) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]

	// --- xray style (string values, only set when non-empty to match the
	// previous protocols/http behaviour) ---
	setIfNotEmpty(data, "cert_subject", leaf.Subject.String())
	setIfNotEmpty(data, "cert_issuer", leaf.Issuer.String())
	setIfNotEmpty(data, "cert_not_before", leaf.NotBefore.Format(xrayTimeLayout))
	setIfNotEmpty(data, "cert_not_after", leaf.NotAfter.Format(xrayTimeLayout))
	setIfNotEmpty(data, "cert_dnsnames", strings.Join(leaf.DNSNames, " "))
	if leaf.SerialNumber != nil {
		setIfNotEmpty(data, "cert_serial", leaf.SerialNumber.String()) // decimal
	}
	setIfNotEmpty(data, "cert_common_name", leaf.Subject.CommonName)
	setIfNotEmpty(data, "cert_organization", strings.Join(leaf.Subject.Organization, " "))

	// --- nuclei style (typed values, always set, mirroring protocols/ssl) ---
	for k, v := range NucleiCertFields(state, sni) {
		data[k] = v
	}

	// raw_cert: the whole presented chain as concatenated DER, for xray-style
	// raw_cert.bcontains(...) matching (printable strings in DER are literal ASCII).
	var raw strings.Builder
	for _, cert := range state.PeerCertificates {
		raw.Write(cert.Raw)
	}
	if raw.Len() > 0 {
		data[common.RawCertKey] = raw.String()
	}
}

// NucleiCertFields returns the nuclei-style certificate/handshake fields for the
// leaf certificate in `state`, mirroring nuclei's `ssl` protocol output. It is
// the single source for both FillCertDSL (which copies it into the response data
// map) and the SSL protocol (which marshals it into the `response` JSON). Returns
// nil when there is no certificate.
func NucleiCertFields(state *tls.ConnectionState, sni string) map[string]interface{} {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	certNames := CertificateNames(leaf)
	mismatched := false
	if sni != "" {
		mismatched = IsMismatchedCert(sni, certNames)
	}
	return map[string]interface{}{
		"subject_cn":           leaf.Subject.CommonName,
		"subject_an":           leaf.DNSNames,
		"subject_dn":           leaf.Subject.String(),
		"subject_org":          leaf.Subject.Organization,
		"issuer_cn":            leaf.Issuer.CommonName,
		"issuer_dn":            leaf.Issuer.String(),
		"issuer_org":           leaf.Issuer.Organization,
		"emails":               leaf.EmailAddresses,
		"serial":               FormatSerial(leaf), // colon-separated hex
		"not_before":           leaf.NotBefore,
		"not_after":            leaf.NotAfter,
		"domains":              UniqueDomains(certNames),
		"wildcard_certificate": IsWildcardName(certNames),
		"self_signed":          IsSelfSigned(leaf),
		"expired":              time.Now().After(leaf.NotAfter),
		"mismatched":           mismatched,
		// untrusted: leaf chain does NOT verify against the system root pool
		// (using the presented intermediates as candidates and the SNI for DNS
		// validation). Mirrors nuclei's `untrusted` DSL field — the strict
		// superset of self_signed+expired+mismatched the upstream tlsx exposes.
		"untrusted": IsUntrusted(state, sni),
		"revoked":     IsRevoked(state),
		"sni":         sni,
		"tls_version": TLSVersionName(state.Version),
		"cipher":      CipherName(state.CipherSuite),
		"fingerprint_hash": FingerprintHash{
			MD5:    CertFingerprint(leaf, "md5"),
			SHA1:   CertFingerprint(leaf, "sha1"),
			SHA256: CertFingerprint(leaf, "sha256"),
		},
		// neutron always handshakes with crypto/tls, which tlsx (the upstream
		// tool) labels "ctls"; emit the engine name to match nuclei.
		"tls_connection": "ctls",
		"probe_status":   true,
	}
}

func setIfNotEmpty(data map[string]interface{}, key, value string) {
	if value != "" {
		data[key] = value
	}
}

// FormatSerial renders the certificate serial number as colon-separated
// uppercase hex (nuclei/tlsx convention), e.g. "0A:1B:2C".
func FormatSerial(cert *x509.Certificate) string {
	if cert.SerialNumber == nil {
		return ""
	}
	b := cert.SerialNumber.Bytes()
	if len(b) == 0 {
		return "00"
	}
	parts := make([]string, len(b))
	for i, by := range b {
		parts[i] = fmt.Sprintf("%02X", by)
	}
	return strings.Join(parts, ":")
}

// CertFingerprint returns the hex digest of the leaf DER under the given algo
// ("md5", "sha1", or anything else → sha256).
func CertFingerprint(cert *x509.Certificate, algo string) string {
	switch algo {
	case "md5":
		sum := md5.Sum(cert.Raw)
		return hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum(cert.Raw)
		return hex.EncodeToString(sum[:])
	default:
		sum := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(sum[:])
	}
}

// CertificateNames returns the leaf CommonName followed by its DNS SANs.
func CertificateNames(cert *x509.Certificate) []string {
	names := make([]string, 0, 1+len(cert.DNSNames))
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	return names
}

// UniqueDomains de-duplicates names, stripping a leading "*." wildcard label.
func UniqueDomains(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	var domains []string
	for _, name := range names {
		domain := strings.TrimPrefix(name, "*.")
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains
}

// IsWildcardName reports whether any name contains a "*." wildcard label.
func IsWildcardName(names []string) bool {
	for _, name := range names {
		if strings.Contains(name, "*.") {
			return true
		}
	}
	return false
}

// IsSelfSigned reports whether the certificate appears self-signed.
func IsSelfSigned(cert *x509.Certificate) bool {
	return len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId)
}

// IsUntrusted reports whether the presented certificate chain fails to verify
// against the system root pool, mirroring nuclei's `untrusted` DSL field.
//
// "Untrusted" includes: self-signed leaves, expired certs, hostname/SAN
// mismatches, unknown CAs, broken signature chains — anything a normal
// browser/HTTPS client would reject. If the system has no CA bundle (e.g. a
// minimal container with no /etc/ssl/certs), we return false: we'd rather miss
// the detection than flag the whole internet as untrusted because of an
// environment quirk. We always pass the leaf SANs through `DNSName` so SNI
// mismatches are surfaced too — keeping `untrusted` a strict superset of
// `mismatched` + `self_signed` + `expired`, the way the upstream tlsx behaves.
func IsUntrusted(state *tls.ConnectionState, sni string) bool {
	if state == nil || len(state.PeerCertificates) == 0 {
		return false
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       sni, // empty string disables hostname verification
		CurrentTime:   time.Now(),
	}
	_, err = state.PeerCertificates[0].Verify(opts)
	return err != nil
}

// RevokeCheckFunc checks whether the leaf cert is revoked via CRL/OCSP.
type RevokeCheckFunc func(state *tls.ConnectionState) bool

var registeredRevokeCheck RevokeCheckFunc

// RegisterRevokeCheck installs a revocation backend. Without registration
// IsRevoked always returns false (safe soft-fail). Import
// _ "github.com/chainreactors/neutron/common/tlsx/full" to enable cfssl.
func RegisterRevokeCheck(f RevokeCheckFunc) { registeredRevokeCheck = f }

// IsRevoked returns true only when a registered backend positively confirms
// the leaf cert is revoked. Soft-fails to false without a backend.
func IsRevoked(state *tls.ConnectionState) bool {
	if registeredRevokeCheck == nil {
		return false
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		return false
	}
	return registeredRevokeCheck(state)
}

// IsMismatchedCert reports whether `host` is NOT covered by any of the
// alternative names (supporting wildcard SANs).
func IsMismatchedCert(host string, alternativeNames []string) bool {
	hostTokens := strings.Split(host, ".")
	for _, alternativeName := range alternativeNames {
		if !strings.Contains(alternativeName, "*") {
			if strings.EqualFold(alternativeName, host) {
				return false
			}
			continue
		}

		nameTokens := strings.Split(alternativeName, ".")
		if len(hostTokens) != len(nameTokens) {
			continue
		}
		matched := false
		for i, token := range nameTokens {
			if i == 0 {
				matched = matchWildcardToken(token, hostTokens[i])
			} else {
				matched = strings.EqualFold(token, hostTokens[i])
			}
			if !matched {
				break
			}
		}
		if matched {
			return false
		}
	}
	return true
}

func matchWildcardToken(name, host string) bool {
	if !strings.Contains(name, "*") {
		return strings.EqualFold(name, host)
	}
	parts := strings.Split(name, "*")
	if strings.HasPrefix(name, "*") {
		return len(parts) > 1 && strings.HasSuffix(host, parts[1])
	}
	if strings.HasSuffix(name, "*") {
		return len(parts) > 0 && strings.HasPrefix(host, parts[0])
	}
	return len(parts) > 1 && strings.HasPrefix(host, parts[0]) && strings.HasSuffix(host, parts[1])
}

// TLSVersionName maps a crypto/tls version constant to its textual name.
// Literal hex values keep this go1.11-safe (tls.VersionTLS13 was added in go1.12).
func TLSVersionName(version uint16) string {
	switch version {
	case 0x0300:
		return "sslv3"
	case 0x0301:
		return "tls10"
	case 0x0302:
		return "tls11"
	case 0x0303:
		return "tls12"
	case 0x0304:
		return "tls13"
	}
	return fmt.Sprintf("0x%04x", version)
}

// cipherNames covers common suites by their crypto/tls constants (all present
// in go1.11). Unknown suites fall back to a hex id.
var cipherNames = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
	// Weak/legacy suites that tls.InsecureCipherSuites() can still negotiate when
	// a template pins an old TLS version. All present as crypto/tls constants in
	// go1.11. Listed explicitly so a negotiated RC4/3DES suite renders as its real
	// name (not a bare hex id) and nuclei's insecure-cipher-suite-detect can match
	// `part: cipher` against e.g. TLS_RSA_WITH_RC4_128_SHA.
	tls.TLS_RSA_WITH_RC4_128_SHA:            "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0x1301:                                  "TLS_AES_128_GCM_SHA256",
	0x1302:                                  "TLS_AES_256_GCM_SHA384",
	0x1303:                                  "TLS_CHACHA20_POLY1305_SHA256",
	0x1304:                                  "TLS_AES_128_CCM_SHA256",
	0x1305:                                  "TLS_AES_128_CCM_8_SHA256",
}

// CipherName maps a cipher suite id to its IANA name, falling back to a hex id.
func CipherName(id uint16) string {
	if name, ok := cipherNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}
