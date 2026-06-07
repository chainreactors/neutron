//go:build !json
// +build !json

package protocols

import (
	"strings"
	"testing"

	"github.com/chainreactors/neutron/common"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func mustVariable(t *testing.T, body string) Variable {
	t.Helper()
	var v Variable
	require.NoError(t, yaml.Unmarshal([]byte(body), &v))
	return v
}

// A random/static variable whose literal text happens to contain the *name* of
// another (unfrozen, target-dependent) variable must still be recognised as
// freezable. The dependency analysis parses the expression instead of substring
// matching, so the literal "token-" is not treated as a reference to `token`.
// Regression for the xray-converted multi-request rules that broke when the old
// regex-based dependency scan saw the literal as a dependency.
func TestStableValuesFreezesRandomWhenLiteralMatchesUnfrozenVariableName(t *testing.T) {
	vars := mustVariable(t, `
token: '{{Hostname}}'
r1: '{{concat("token-", rand_base(8, "abc"))}}'
`)
	frozen := vars.StableValues()

	r1, ok := frozen["r1"]
	require.True(t, ok, "r1 (random + literal) must be frozen")
	require.True(t, strings.HasPrefix(common.ToString(r1), "token-"))

	_, ok = frozen["token"]
	require.False(t, ok, "token depends on {{Hostname}} and must stay per-request")
}

// A variable that depends on a runtime identifier (an extractor output, here
// `seed`) must not be frozen — its value is only known at request time.
func TestStableValuesKeepsRuntimeDependentVariableUnfrozen(t *testing.T) {
	vars := mustVariable(t, `
token: '{{concat("accepted-", seed)}}'
`)
	frozen := vars.StableValues()
	_, ok := frozen["token"]
	require.False(t, ok, "token depends on runtime `seed` and must not be frozen")
}

// A stable variable that references a previously defined stable variable is
// frozen too, matching nuclei's insertion-order evaluation.
func TestStableValuesFreezesChainedStaticVariables(t *testing.T) {
	vars := mustVariable(t, `
a: '{{rand_base(6, "x")}}'
b: '{{a}}-suffix'
`)
	frozen := vars.StableValues()

	require.Contains(t, frozen, "a")
	require.Contains(t, frozen, "b")
	require.Equal(t, common.ToString(frozen["a"])+"-suffix", common.ToString(frozen["b"]))
}

func TestStableValuesDoesNotResolveLaterVariablesOutOfOrder(t *testing.T) {
	vars := mustVariable(t, `
b: '{{a}}-suffix'
a: foo
`)
	frozen := vars.StableValues()

	require.Contains(t, frozen, "a")
	require.NotContains(t, frozen, "b", "nuclei evaluates variables in definition order, not by multi-pass backfill")
}

func TestStableValuesFreezesResolvedValueContainingParenthesis(t *testing.T) {
	vars := mustVariable(t, `r1: '{{rand_base(1, "(")}}'`)
	frozen := vars.StableValues()

	require.Equal(t, "(", common.ToString(frozen["r1"]))
}

// WithFrozen pins the frozen keys to their literal value so re-evaluating the
// view across request blocks yields the same value, while unfrozen keys keep
// their original definition and are re-evaluated per call.
func TestWithFrozenPinsFrozenKeysAndReevaluatesOthers(t *testing.T) {
	vars := mustVariable(t, `
token: '{{Hostname}}'
r1: '{{concat("token-", rand_base(8, "abc"))}}'
`)
	frozen := vars.StableValues()
	baked := vars.WithFrozen(frozen)

	first := baked.Evaluate(map[string]interface{}{"Hostname": "host-a"})
	second := baked.Evaluate(map[string]interface{}{"Hostname": "host-b"})

	// frozen r1 is identical across blocks
	require.Equal(t, first["r1"], second["r1"])
	require.Equal(t, common.ToString(frozen["r1"]), common.ToString(first["r1"]))
	// unfrozen token still tracks the per-request target value
	require.Equal(t, "host-a", first["token"])
	require.Equal(t, "host-b", second["token"])
}

// WithFrozen with nothing to freeze is an identity: the random variable is
// re-evaluated on every call.
func TestWithFrozenEmptyReevaluatesRandom(t *testing.T) {
	vars := mustVariable(t, `r1: '{{rand_base(10, "abcdefghij")}}'`)

	baked := vars.WithFrozen(nil)
	a := baked.Evaluate(map[string]interface{}{})
	b := baked.Evaluate(map[string]interface{}{})
	require.NotEqual(t, a["r1"], b["r1"], "without freezing, random re-rolls each call")
}

// Evaluate evaluates each variable's own definition, so a template variable
// shadows a builtin/runtime value of the same name. This is the guard that the
// magic-key and naive-layering approaches both broke.
func TestEvaluateTemplateVariableShadowsBuiltin(t *testing.T) {
	vars := mustVariable(t, `randstr: template-randstr`)
	out := vars.Evaluate(map[string]interface{}{"randstr": "global-generated"})
	require.Equal(t, "template-randstr", out["randstr"])
}
