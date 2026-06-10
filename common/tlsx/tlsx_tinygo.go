//go:build tinygo
// +build tinygo

package tlsx

import "crypto/tls"

func FillCertDSL(data map[string]interface{}, state *tls.ConnectionState, sni string) {}
