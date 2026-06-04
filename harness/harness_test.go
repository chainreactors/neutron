package harness

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/chainreactors/neutron/convert"
)

func loadTestPOC(t *testing.T, raw string) *convert.XrayPOC {
	t.Helper()
	var poc convert.XrayPOC
	require.NoError(t, yaml.Unmarshal([]byte(raw), &poc))
	return &poc
}

func TestVerifySimplePositiveScenario(t *testing.T) {
	raw := `
name: harness-simple
transport: http
rules:
  r0:
    request:
      method: GET
      path: /login
    expression: response.status == 201 && response.body_string.contains("welcome")
expression: r0()
`
	report := VerifyFile(&POCFile{Path: "simple.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
	require.True(t, report.Matched)
}

func TestVerifyUnsupportedImpossibleHTTPStatus(t *testing.T) {
	raw := `
name: harness-impossible-status
transport: http
rules:
  r0:
    request:
      method: GET
      path: /status
    expression: response.status < 2
expression: r0()
`
	report := VerifyFile(&POCFile{Path: "status.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusUnsupported, report.Status)
	require.Contains(t, report.Unsupported, "cannot generate valid HTTP status for response.status < 2")
}

func TestChooseStatusCodeSolvesHTTPRange(t *testing.T) {
	tests := []struct {
		op     string
		target int
		want   int
		ok     bool
	}{
		{op: "==", target: 200, want: 200, ok: true},
		{op: "!=", target: 200, want: 201, ok: true},
		{op: "!=", target: 700, want: 200, ok: true},
		{op: ">", target: 99, want: 100, ok: true},
		{op: ">", target: 599, ok: false},
		{op: ">=", target: 0, want: 100, ok: true},
		{op: "<", target: 101, want: 100, ok: true},
		{op: "<", target: 2, ok: false},
		{op: "<=", target: 700, want: 599, ok: true},
		{op: "<=", target: 99, ok: false},
	}

	for _, tt := range tests {
		got, ok := chooseStatusCode(tt.op, tt.target)
		require.Equal(t, tt.ok, ok, "%s %d", tt.op, tt.target)
		if tt.ok {
			require.Equal(t, tt.want, got, "%s %d", tt.op, tt.target)
		}
	}
}

func TestVerifyOutputVariablePathChain(t *testing.T) {
	raw := `
name: harness-output-chain
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("asset")
    output:
      search: '"src=\"(?P<asset>/static/app\.[a-z0-9]+\.js)\"".submatch(response.body_string)'
      asset_path: search["asset"]
  fetch:
    request:
      method: GET
      path: /{{asset_path}}
    expression: response.body_string.contains("boot complete")
expression: discover() && fetch()
`
	report := VerifyFile(&POCFile{Path: "chain.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
}

func TestVerifyOutputTransformPathChain(t *testing.T) {
	raw := `
name: harness-output-transform-chain
transport: http
rules:
  discover:
    request:
      method: GET
      path: /upload
    expression: response.status == 200 && response.body_string.contains(".php")
    output:
      search: |-
        "(?P<path>public\\\\/shell.php)".bsubmatch(response.body)
      upload_path: replaceAll(search["path"], "\\", "")
  fetch:
    request:
      method: GET
      path: /{{upload_path}}
    expression: response.status == 200 && response.body_string.contains("shell")
expression: discover() && fetch()
`
	report := VerifyFile(&POCFile{Path: "transform.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
}

func TestVerifyBase64DecodedOutputHint(t *testing.T) {
	raw := `
name: harness-output-base64-transform
transport: http
rules:
  read:
    request:
      method: GET
      path: /read
    expression: response.body_string.contains("blob")
    output:
      search: |-
        "blob:(?P<decoded>.+?)".bsubmatch(response.body)
      decoded: base64Decode(string(search["decoded"]))
  check:
    expression: string(b"marker-value").bmatches(bytes(decoded))
expression: read() && check()
`
	report := VerifyFile(&POCFile{Path: "base64.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
}

func TestVerifyTreatsSleepAsHarnessSideEffect(t *testing.T) {
	raw := `
name: harness-sleep
transport: http
rules:
  create:
    request:
      method: POST
      path: /items
    expression: response.status == 201 && sleep(20)
  fetch:
    request:
      method: GET
      path: /items/1
    expression: response.status == 200
expression: create() && fetch()
`
	report := VerifyFile(&POCFile{Path: "sleep.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
}

func TestVerifyChoosesOneORBranch(t *testing.T) {
	raw := `
name: harness-or
transport: http
rules:
  weak:
    request:
      method: GET
      path: /weak
    expression: response.status == 404
  strong:
    request:
      method: GET
      path: /strong
    expression: response.status == 200 && response.body_string.contains("strong-hit")
expression: weak() || strong()
`
	report := VerifyFile(&POCFile{Path: "or.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
	require.GreaterOrEqual(t, report.SupportedScenarios, 1)
}

func TestVerifyRendersTemplatePlaceholdersInResponseLiterals(t *testing.T) {
	raw := `
name: harness-render-literal
transport: http
set:
  token: randomLowercase(6)
rules:
  r0:
    request:
      method: GET
      path: /echo/{{token}}
    expression: response.status == 200 && response.body_string.contains("token={{token}}")
expression: r0()
`
	report := VerifyFile(&POCFile{Path: "render.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
}

func TestVerifyLatencyLowerBoundHasRuntimeMargin(t *testing.T) {
	raw := `
name: harness-latency-margin
transport: http
rules:
  baseline:
    request:
      method: GET
      path: /baseline
    expression: response.status == 200
    output:
      r0latency: response.latency
  delayed:
    request:
      method: GET
      path: /delayed
    expression: response.status == 200 && response.latency - r0latency >= 20
expression: baseline() && delayed()
`
	report := VerifyFile(&POCFile{Path: "latency.yml", Data: []byte(raw), POC: loadTestPOC(t, raw)}, VerifyOptions{})
	require.Equal(t, StatusOK, report.Status, report.Reason)
}

func TestDeriveSetVariablesInfersRandomDependenciesFromEncodedConcat(t *testing.T) {
	exprs := map[string]string{
		"s1": "randomInt(40000, 44800)",
		"s2": "randomInt(40000, 44800)",
		"s3": `string("<%out.print(") + string(s1) + string(" * ") + string(s2) + string(");%>")`,
		"s4": "base64(s3)",
	}
	s3 := "<%out.print(43286 * 44431);%>"
	values := map[string]string{
		"s1": "40000",
		"s2": "40000",
		"s3": "harness",
		"s4": base64.StdEncoding.EncodeToString([]byte(s3)),
	}

	deriveSetVariables(exprs, values)

	require.Equal(t, "43286", values["s1"])
	require.Equal(t, "44431", values["s2"])
	require.Equal(t, s3, values["s3"])
}

func TestDeriveSetVariablesInfersBytesDependencyFromBFormat(t *testing.T) {
	actual := "0123456789abcdef0123456789abcdef"
	exprs := map[string]string{
		"md5rand":   "md5(string(randomLowercase(15)))",
		"randbytes": "bytes(md5rand)",
		"16str":     `randbytes.bformat(16, 0, "", 0)`,
	}
	values := map[string]string{
		"md5rand":   "harness",
		"randbytes": "harness",
		"16str":     hex.EncodeToString([]byte(actual)),
	}

	deriveSetVariables(exprs, values)

	require.Equal(t, actual, values["md5rand"])
	require.Equal(t, actual, values["randbytes"])
}

func TestDeriveSetVariablesEvaluatesBytesDependencyWhenValueIsSynthetic(t *testing.T) {
	r1 := "gypxpvoivhqqdwj"
	expected := fmt.Sprintf("%x", md5.Sum([]byte(r1)))
	exprs := map[string]string{
		"r1":        "randomLowercase(15)",
		"md5rand":   "md5(string(r1))",
		"randbytes": "bytes(md5rand)",
	}
	values := map[string]string{
		"r1":        r1,
		"md5rand":   "harness",
		"randbytes": "harness",
	}

	deriveSetVariables(exprs, values)

	require.Equal(t, expected, values["md5rand"])
	require.Equal(t, expected, values["randbytes"])
}

func TestRegexSamplePreservesLiteralOpeningBrace(t *testing.T) {
	pattern := `{"data":".*admin\s?(?P<password>[^\\"]*)`
	sample := regexSample(pattern, groupHints{})

	require.Regexp(t, pattern, sample)
	require.Contains(t, sample, `{"data":`)
}
