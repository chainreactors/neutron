//go:build go1.14
// +build go1.14

package ssl

import (
	"crypto/tls"
	"strings"
)

func allCipherSuiteIDs() []uint16 {
	var all []uint16
	for _, c := range tls.CipherSuites() {
		all = append(all, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		all = append(all, c.ID)
	}
	return all
}

func cipherSuiteID(name string) (uint16, bool) {
	for _, suite := range tls.CipherSuites() {
		if strings.EqualFold(suite.Name, name) {
			return suite.ID, true
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if strings.EqualFold(suite.Name, name) {
			return suite.ID, true
		}
	}
	return 0, false
}
