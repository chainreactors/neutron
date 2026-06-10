package convert

import (
	"testing"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/dsl"
)

// TestCertRegistryParity guards the single-source-of-truth invariant between
// common.XrayCertFields (which decides what xray cert subfields are
// evaluable) and dsl.CertDataKeys (the keys every Emitter partMap is
// required to map explicitly).
//
// The Emitter Field() fallback used to catch unmapped cert_* via a
// strings.HasPrefix("cert") branch; removing that branch means any cert key
// that is NOT explicitly mapped silently falls into the header default and
// gets rewritten as `header="cert_xxx: ..."` by isHeaderVariable. This test
// makes that drift loud.
func TestCertRegistryParity(t *testing.T) {
	declared := make(map[string]bool, len(dsl.CertDataKeys))
	for _, key := range dsl.CertDataKeys {
		declared[key] = true
	}

	// 1. Every value in common.XrayCertFields must appear in dsl.CertDataKeys.
	for sub, key := range common.XrayCertFields {
		if !declared[key] {
			t.Errorf("XrayCertFields[%q] = %q missing from dsl.CertDataKeys", sub, key)
		}
	}

	// 2. raw_cert (response.raw_cert.bcontains) must also be listed: it
	// reaches the emitter as a NodeVariable just like the other cert keys.
	if !declared[common.RawCertKey] {
		t.Errorf("common.RawCertKey = %q missing from dsl.CertDataKeys", common.RawCertKey)
	}

	// 3. Every dsl.CertDataKeys entry must resolve to a non-default field on
	// every emitter — otherwise it would be misclassified as a header
	// variable (see isHeaderVariable in codegen.go).
	for _, platform := range []string{"fofa", "hunter", "censys"} {
		e, ok := dsl.GetEmitter(platform)
		if !ok {
			t.Fatalf("emitter %q not registered", platform)
		}
		// A synthetic part name no real query would use → exercises the
		// emitter's default branch. Any cert key resolving to the same value
		// means it fell through to header.
		defaultField := e.Field("__unmapped_synthetic_part__")
		for _, key := range dsl.CertDataKeys {
			got := e.Field(key)
			if got == defaultField {
				t.Errorf("[%s] cert key %q falls through to default field %q — partMap missing explicit mapping", platform, key, got)
			}
		}
	}
}
