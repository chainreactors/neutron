//go:build tinygo
// +build tinygo

package http

import "net/http"

func addTLSCertFields(data map[string]interface{}, resp *http.Response) {}
