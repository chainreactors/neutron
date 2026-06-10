//go:build !tinygo
// +build !tinygo

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
)

type CertificateFingerprintHash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

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

func CertificateNames(cert *x509.Certificate) []string {
	names := make([]string, 0, 1+len(cert.DNSNames))
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	return names
}

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

func IsWildcardName(names []string) bool {
	for _, name := range names {
		if strings.Contains(name, "*.") {
			return true
		}
	}
	return false
}

func IsSelfSigned(cert *x509.Certificate) bool {
	return len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId)
}

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
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
}

func CipherName(id uint16) string {
	if name, ok := cipherNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}
