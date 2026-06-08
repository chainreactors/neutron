//go:build json
// +build json

package protocols

import (
	"testing"

	"github.com/chainreactors/neutron/common"
	"github.com/stretchr/testify/require"
)

func TestJSONStableValuesFreezesResolvedValueContainingParenthesis(t *testing.T) {
	vars := Variable{"r1": `{{rand_base(1, "(")}}`}
	frozen := vars.StableValues()

	require.Equal(t, "(", common.ToString(frozen["r1"]))
}

func TestJSONStableValuesKeepsRuntimeDependentVariableUnfrozen(t *testing.T) {
	vars := Variable{"token": `{{concat("accepted-", seed)}}`}
	frozen := vars.StableValues()

	require.NotContains(t, frozen, "token")
}

func TestJSONEvaluateTemplateVariableShadowsBuiltin(t *testing.T) {
	vars := Variable{"randstr": "template-randstr"}
	out := vars.Evaluate(map[string]interface{}{"randstr": "global-generated"})
	require.Equal(t, "template-randstr", out["randstr"])
}
