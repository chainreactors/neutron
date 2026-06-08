//go:build !tinygo
// +build !tinygo

package http

import (
	"testing"

	"github.com/chainreactors/neutron/common"
)

// TestCertFieldRegistryParity guards the single-source-of-truth invariant:
// every cert data key declared in common.XrayCertFields must have a matching
// extractor here, and vice versa. This prevents the converter and the runtime
// from drifting apart when a cert field is added.
func TestCertFieldRegistryParity(t *testing.T) {
	// Every xray-mapped key must have an extractor.
	for sub, key := range common.XrayCertFields {
		if _, ok := certExtractors[key]; !ok {
			t.Errorf("XrayCertFields[%q] -> %q has no extractor in certExtractors", sub, key)
		}
	}
	// Every extractor must be referenced by at least one xray field.
	referenced := make(map[string]bool, len(common.XrayCertFields))
	for _, key := range common.XrayCertFields {
		referenced[key] = true
	}
	for key := range certExtractors {
		if !referenced[key] {
			t.Errorf("certExtractors[%q] is not referenced by any XrayCertFields entry", key)
		}
	}
}
