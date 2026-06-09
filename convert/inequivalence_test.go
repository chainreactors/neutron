package convert

import (
	"strings"
	"testing"

	"github.com/chainreactors/words/logic"
	"gopkg.in/yaml.v3"
)

// ====================================================================
// Issue 1 [HIGH]: AND within same group in multi-group OR
//
// expression: (r0() && r1()) || r2()
// r0, r1 share path /, r2 has path /admin
//
// buildIndependentBlocks combines r0||r1 inside group instead of r0&&r1
// because it always uses "||" to join within-group rules.
// ====================================================================

func TestInequivalence_ANDWithinSameGroupMultiGroup(t *testing.T) {
	xray := `
name: test-and-within-group
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("marker-A")
  r1:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("marker-B")
  r2:
    request:
      method: GET
      path: /admin
    expression: response.body_string.contains("admin-panel")
expression: (r0() && r1()) || r2()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	// Key case: body has marker-A but NOT marker-B.
	// xray: r0()=true, r1()=false → r0()&&r1()=false, r2()=false → false
	// If buggy (r0||r1 instead of r0&&r1): marker-A matches → true (WRONG)
	resp := mockResponse{200, "marker-A only", nil}

	xrayR := xrayEvalPOC(xray, map[string]mockResponse{"default": resp})
	neutronR := neutronEval(conv, resp)

	if xrayR != false {
		t.Errorf("xray should be false, got %v", xrayR)
	}
	if xrayR != neutronR {
		t.Errorf("INEQUIVALENT: xray=%v neutron=%v — AND within group was lost", xrayR, neutronR)
	}

	// Positive case: body has both markers
	resp2 := mockResponse{200, "marker-A marker-B", nil}
	xrayR2 := xrayEvalPOC(xray, map[string]mockResponse{"default": resp2})
	neutronR2 := neutronEval(conv, resp2)
	if xrayR2 != true {
		t.Errorf("xray should be true for both markers")
	}
	if xrayR2 != neutronR2 {
		t.Errorf("INEQUIVALENT positive case: xray=%v neutron=%v", xrayR2, neutronR2)
	}
}

// ====================================================================
// Issue 2 [MEDIUM]: isTooPermissive silently drops OR matchers
//
// status==200 || body.contains("marker") → drops status==200
// A response with status 200 but no "marker" should match in xray
// but won't match in neutron.
// ====================================================================

func TestInequivalence_TooPermissiveDropsORMatcher(t *testing.T) {
	xray := `
name: test-too-permissive
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 || response.body_string.contains("unique-marker-xyz")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	// Response: status 200 but body doesn't have the marker
	// xray: status==200 → true (OR short-circuits)
	// neutron: status==200 dropped as too permissive → only checks marker → false
	resp := mockResponse{200, "<html>Hello World</html>", nil}

	xrayR := xrayEval(`response.status == 200 || response.body_string.contains("unique-marker-xyz")`, resp)
	neutronR := neutronEval(conv, resp)

	if xrayR != true {
		t.Errorf("xray should be true (status 200 matches OR)")
	}
	if xrayR != neutronR {
		t.Errorf("INEQUIVALENT: xray=%v neutron=%v — status dropped by isTooPermissive", xrayR, neutronR)
	}
}

// ====================================================================
// Issue 3 [MEDIUM]: response.raw_header normalization mismatch
//
// xray: response.raw_header.bcontains(b"X-Jenkins") — searches
//       original header bytes "X-Jenkins: value\r\n"
// neutron: contains(all_headers, "X-Jenkins") — but all_headers has
//          normalized keys "x_jenkins: value\r\n", so "X-Jenkins" not found
// ====================================================================

func TestInequivalence_RawHeaderNormalization(t *testing.T) {
	xray := `
name: test-raw-header
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.raw_header.bcontains(b"X-Jenkins")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	resp := mockResponse{200, "", map[string]string{"X-Jenkins": "2.440"}}

	xrayR := xrayEval(`response.raw_header.bcontains(b"X-Jenkins")`, resp)
	neutronR := neutronEval(conv, resp)

	if xrayR != true {
		t.Errorf("xray should match X-Jenkins in raw header")
	}
	if xrayR != neutronR {
		t.Errorf("INEQUIVALENT: xray=%v neutron=%v — raw_header normalization gap (X-Jenkins vs x_jenkins)", xrayR, neutronR)
	}
}

// ====================================================================
// Previously Issue 4 [LOW]: response.cert stub dropped AND constraints.
//
// The shared tlsx pipeline now evaluates response.cert.* natively, so
// `cert.check() && body.check()` keeps BOTH constraints instead of silently
// degrading to just the body check (which used to cause false positives).
// ====================================================================

func TestCertConstraintPreservedInAnd(t *testing.T) {
	result, err := ExprToMatchers(`response.cert.issuer.contains("Example Corp") && response.body.contains("login")`)
	if err != nil {
		t.Fatal(err)
	}
	if result.MatchersCondition != "and" {
		t.Fatalf("expected AND condition preserved, got %q", result.MatchersCondition)
	}
	if len(result.Matchers) != 2 {
		t.Fatalf("expected 2 matchers (cert + body), got %d", len(result.Matchers))
	}
	found := false
	for _, m := range result.Matchers {
		for _, d := range m.DSL {
			if strings.Contains(d, "cert_issuer") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("cert_issuer matcher missing: %+v", result.Matchers)
	}
}

// ====================================================================
// Issue 5 [LOW]: Operator precedence in top-level expression
//
// r0() || r1() && r2() means r0() || (r1() && r2()) per standard precedence
// Check the top-level parser respects this.
// ====================================================================

func TestInequivalence_TopExprPrecedence(t *testing.T) {
	node := parseTopExpression("r0() || r1() && r2()")
	if node == nil {
		t.Fatal("parse failed")
	}
	// Should be: or(r0, and(r1, r2))
	if node.Type != "or" {
		t.Fatalf("top should be OR, got %s", node.Type)
	}
	if len(node.Children) != 2 {
		t.Fatalf("OR should have 2 children, got %d", len(node.Children))
	}
	if node.Children[0].Type != "call" || node.Children[0].Name != "r0" {
		t.Errorf("first child should be call(r0), got %+v", node.Children[0])
	}
	if node.Children[1].Type != "and" {
		t.Errorf("second child should be AND, got %s", node.Children[1].Type)
	}
}

// ====================================================================
// Issue 6 [LOW]: Multiple rules with same path but different expression
// operators — buildIndependentBlocks with top-level OR is correct
// ====================================================================

func TestEquivalence_PureORMultiGroup(t *testing.T) {
	xray := `
name: test-pure-or
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("marker-A")
  r1:
    request:
      method: GET
      path: /admin
    expression: response.body_string.contains("admin-panel")
expression: r0() || r1()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}

	// Should NOT have req-condition for pure OR
	if strings.Contains(string(conv), "req-condition") {
		t.Error("pure OR should not use req-condition")
	}

	resp := mockResponse{200, "marker-A content", nil}
	xrayR := xrayEvalPOC(xray, map[string]mockResponse{"default": resp})
	neutronR := neutronEval(conv, resp)
	if xrayR != neutronR {
		t.Errorf("INEQUIVALENT pure OR: xray=%v neutron=%v", xrayR, neutronR)
	}
}

// ====================================================================
// Logic-based equivalence verification
//
// Uses words/logic to evaluate the xray top-level expression against
// per-rule match results, then compares with neutron template evaluation.
// This is the authoritative equivalence check.
// ====================================================================

func TestLogicEquivalence_Exhaustive(t *testing.T) {
	cases := []struct {
		name  string
		xray  string
		resps []mockResponse
	}{
		{
			"AND_same_path",
			`
name: test
transport: http
rules:
  r0:
    request: {method: GET, path: /}
    expression: response.body_string.contains("alpha")
  r1:
    request: {method: GET, path: /}
    expression: response.body_string.contains("beta")
expression: r0() && r1()
`,
			[]mockResponse{
				{200, "alpha beta", nil},
				{200, "alpha only", nil},
				{200, "beta only", nil},
				{200, "nothing", nil},
			},
		},
		{
			"OR_different_path",
			`
name: test
transport: http
rules:
  r0:
    request: {method: GET, path: /}
    expression: response.body_string.contains("marker")
  r1:
    request: {method: GET, path: /admin}
    expression: response.body_string.contains("panel")
expression: r0() || r1()
`,
			[]mockResponse{
				{200, "marker panel", nil},
				{200, "marker only", nil},
				{200, "panel only", nil},
				{200, "nothing", nil},
			},
		},
		{
			"mixed_AND_OR",
			`
name: test
transport: http
rules:
  r0:
    request: {method: GET, path: /}
    expression: response.body_string.contains("A")
  r1:
    request: {method: GET, path: /}
    expression: response.body_string.contains("B")
  r2:
    request: {method: GET, path: /alt}
    expression: response.body_string.contains("C")
expression: (r0() && r1()) || r2()
`,
			[]mockResponse{
				{200, "A B C", nil},
				{200, "A B", nil},
				{200, "A only", nil},
				{200, "C only", nil},
				{200, "nothing", nil},
			},
		},
		{
			"optional_version",
			`
name: test
transport: http
rules:
  r0:
    request: {method: GET, path: /}
    expression: response.body_string.contains("product")
  r1:
    request: {method: GET, path: /ver}
    expression: response.status == 200
expression: r0() && (r1() || true)
`,
			[]mockResponse{
				{200, "product here", nil},
				{404, "product here", nil},
				{200, "nothing", nil},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conv, err := Convert([]byte(tc.xray))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("converted:\n%s", conv)

			for i, resp := range tc.resps {
				// Ground truth: evaluate xray per-rule, then combine with logic.Run
				xrayPerRule := xrayEvalPOCPerRule(tc.xray, resp)
				topExprStr := extractTopExpression(tc.xray)
				expected := logic.Run(topExprStr, xrayPerRule)

				// Neutron evaluation
				neutronR := neutronEval(conv, resp)

				if expected != neutronR {
					t.Errorf("resp[%d] body=%q: logic=%v neutron=%v (rules=%v)",
						i, resp.Body, expected, neutronR, xrayPerRule)
				}
			}
		})
	}
}

// xrayEvalPOCPerRule evaluates each rule independently against the response
// and returns a map[string]bool suitable for logic.Run.
func xrayEvalPOCPerRule(pocYAML string, resp mockResponse) map[string]bool {
	var poc struct {
		Rules map[string]struct {
			Expression string `yaml:"expression"`
		} `yaml:"rules"`
	}
	yaml.Unmarshal([]byte(pocYAML), &poc)

	env := map[string]bool{}
	for name, rule := range poc.Rules {
		env[name] = xrayEval(rule.Expression, resp)
	}
	return env
}

// extractTopExpression parses the xray top-level expression and returns
// a clean logic string with bare identifiers (no function call "()" syntax).
func extractTopExpression(pocYAML string) string {
	var poc struct {
		Expression string `yaml:"expression"`
	}
	yaml.Unmarshal([]byte(pocYAML), &poc)
	node := parseTopExpression(poc.Expression)
	return topExprToString(node)
}
