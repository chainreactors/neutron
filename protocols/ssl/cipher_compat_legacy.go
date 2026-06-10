//go:build !go1.14
// +build !go1.14

package ssl

import (
	"crypto/tls"
	"strings"
)

// Pre-go1.14 fallback: use the cipherNames map from common/tlsx as the
// known cipher universe (tls.CipherSuites/InsecureCipherSuites unavailable).

func allCipherSuiteIDs() []uint16 {
	var all []uint16
	for id := range legacyCipherNames {
		all = append(all, id)
	}
	return all
}

func cipherSuiteID(name string) (uint16, bool) {
	for id, n := range legacyCipherNames {
		if strings.EqualFold(n, name) {
			return id, true
		}
	}
	return 0, false
}

var legacyCipherNames = map[uint16]string{
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
	tls.TLS_RSA_WITH_RC4_128_SHA:                 "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:           "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:         "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
