package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"gopkg.in/yaml.v3"
)

func newTestRequest(t *testing.T, matchers []*operators.Matcher) *Request {
	t.Helper()
	r := &Request{}
	r.Operators = operators.Operators{Matchers: matchers}
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	if err := r.Compile(opts); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return r
}

func runAgainst(t *testing.T, r *Request, target string) *operators.Result {
	t.Helper()
	ctx := protocols.NewScanContext(target, nil)
	var got *operators.Result
	err := r.ExecuteWithResults(ctx, map[string]interface{}{}, map[string]interface{}{}, func(e *protocols.InternalWrappedEvent) {
		if e.OperatorsResult != nil {
			got = e.OperatorsResult
		}
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return got
}

func TestSSLCertMatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	// httptest's TLS server uses a cert with CN "127.0.0.1" / Org "Acme Co".
	target := strings.TrimPrefix(server.URL, "https://")

	r := newTestRequest(t, []*operators.Matcher{
		{Type: "dsl", DSL: []string{`contains(subject_org, "Acme")`}},
		{Type: "dsl", DSL: []string{`contains(tls_version, "tls")`}},
	})
	r.Operators.MatchersCondition = "and"
	if err := r.CompiledOperators.Compile(); err != nil {
		t.Fatalf("recompile: %v", err)
	}

	result := runAgainst(t, r, target)
	if result == nil || !result.Matched {
		t.Fatalf("expected cert match against %s, got %+v", target, result)
	}
}

func TestSSLDefaultTargetAcceptsFullURLWithPath(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	r := newTestRequest(t, []*operators.Matcher{
		{Type: "dsl", DSL: []string{`probe_status == true`}},
	})
	result := runAgainst(t, r, server.URL+"/nested/path")
	if result == nil || !result.Matched {
		t.Fatalf("expected SSL default target to normalize full URL, got %+v", result)
	}
}

func TestSSLAddressYAML(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	var wrapper struct {
		SSL []*Request `yaml:"ssl"`
	}
	raw := `
ssl:
  - address: "{{Host}}:{{Port}}"
    matchers:
      - type: dsl
        dsl:
          - probe_status == true
`
	if err := yaml.Unmarshal([]byte(raw), &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(wrapper.SSL) != 1 || wrapper.SSL[0].Address != "{{Host}}:{{Port}}" {
		t.Fatalf("expected scalar address to decode as canonical address: %+v", wrapper.SSL)
	}
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	if err := wrapper.SSL[0].Compile(opts); err != nil {
		t.Fatalf("compile: %v", err)
	}
	result := runAgainst(t, wrapper.SSL[0], server.URL+"/from/input/path")
	if result == nil || !result.Matched {
		t.Fatalf("expected address template to match, got %+v", result)
	}
}

func TestSSLCompileRejectsUnsupportedNucleiOptions(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"version_enum", Request{TLSVersionEnum: true}, "tls_version_enum"},
		{"cipher_enum", Request{TLSCipherEnum: true}, "tls_cipher_enum"},
		{"cipher_types", Request{TLSCipherTypes: true}, "tls_cipher_types"},
		{"ztls_scan_mode", Request{ScanMode: "ztls"}, "scan_mode=ztls"},
		{"unknown_cipher", Request{CipherSuites: []string{"TLS_FAKE_WITH_NOTHING"}}, "unsupported tls cipher suite"},
		{"tls13_cipher", Request{CipherSuites: []string{"TLS_AES_128_GCM_SHA256"}}, "not configurable"},
	}
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Compile(opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected compile error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestSSLCompileAcceptsCipherSuitesAndCTLSMode(t *testing.T) {
	r := &Request{
		ScanMode:     "ctls",
		CipherSuites: []string{"TLS_RSA_WITH_AES_128_CBC_SHA"},
	}
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	if err := r.Compile(opts); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(r.cipherSuites) != 1 || r.cipherSuites[0] != tls.TLS_RSA_WITH_AES_128_CBC_SHA {
		t.Fatalf("unexpected cipher ids: %#v", r.cipherSuites)
	}
}

func TestSSLCompileRejectsRevokedWithoutBackend(t *testing.T) {
	r := &Request{
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{
				{Type: "dsl", DSL: []string{`revoked == true`}},
			},
		},
	}
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	err := r.Compile(opts)
	if err == nil || !strings.Contains(err.Error(), "no revocation backend") {
		t.Fatalf("expected missing revocation backend error, got %v", err)
	}
}

func TestSSLCompileDoesNotFalseRejectRevokedSubstring(t *testing.T) {
	r := &Request{
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{
				{Type: "dsl", DSL: []string{`not_revoked == true`}},
			},
		},
	}
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	if err := r.Compile(opts); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestSSLRawCertAndFingerprint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	target := strings.TrimPrefix(server.URL, "https://")

	// raw_cert should carry the org string from the DER, and response should
	// expose the tlsx-compatible fingerprint_hash object.
	r := newTestRequest(t, []*operators.Matcher{
		{Type: "dsl", DSL: []string{`contains(raw_cert, "Acme")`}},
		{Type: "regex", Part: "response", Regex: []string{`"sha256":"[0-9a-f]{64}"`}},
	})
	r.Operators.MatchersCondition = "and"
	if err := r.CompiledOperators.Compile(); err != nil {
		t.Fatalf("recompile: %v", err)
	}

	result := runAgainst(t, r, target)
	if result == nil || !result.Matched {
		t.Fatalf("expected raw_cert/fingerprint match against %s, got %+v", target, result)
	}
}

func TestSSLResponseFieldsMatchNucleiShape(t *testing.T) {
	notBefore := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	notAfter := time.Date(2120, 1, 2, 3, 4, 5, 0, time.UTC)
	cert := &x509.Certificate{
		Raw:            []byte("certificate-bytes"),
		DNSNames:       []string{"one.example", "two.example"},
		EmailAddresses: []string{"admin@example.com"},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		SerialNumber:   big.NewInt(0x1234),
		Subject: pkix.Name{
			CommonName:   "leaf",
			Organization: []string{"Org"},
		},
		Issuer: pkix.Name{CommonName: "issuer"},
	}
	state := &tls.ConnectionState{
		Version:          0x0304,
		CipherSuite:      0x1301,
		ServerName:       "one.example",
		PeerCertificates: []*x509.Certificate{cert},
	}
	data := map[string]interface{}{}

	(&Request{}).responseToDSLMap(data, "one.example:443", nil, state)

	if data["probe_status"] != true || data["tls_connection"] != "ctls" {
		t.Fatalf("missing nuclei status fields: %+v", data)
	}
	fp, ok := data["fingerprint_hash"].(certificateFingerprintHash)
	if !ok || len(fp.SHA256) != 64 || len(fp.SHA1) != 40 || len(fp.MD5) != 32 {
		t.Fatalf("fingerprint_hash should be the tlsx object shape: %#v", data["fingerprint_hash"])
	}
	if _, ok := data["fingerprint_hash.sha256"]; ok {
		t.Fatalf("unexpected dotted fingerprint fallback key: %+v", data)
	}
	if _, ok := data["fingerprint_sha256"]; ok {
		t.Fatalf("unexpected flat fingerprint fallback key: %+v", data)
	}
	if _, ok := data["expired"].(bool); !ok {
		t.Fatalf("expired flag should be a bool: %+v", data)
	}
	if data["expired"] != false || data["mismatched"] != false {
		t.Fatalf("unexpected certificate state flags: %+v", data)
	}
	if got := data["domains"].([]string); !sameStrings(got, []string{"leaf", "one.example", "two.example"}) {
		t.Fatalf("unexpected nuclei domains shape: %#v", got)
	}
	if data["sni"] != "one.example" || data["subject_cn"] != "leaf" {
		t.Fatalf("missing domain/sni fields: %+v", data)
	}
	if data["serial"] != "12:34" {
		t.Fatalf("unexpected serial format: %v", data["serial"])
	}
	if data["cipher"] != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected TLS 1.3 cipher name: %v", data["cipher"])
	}
	if got, ok := data["not_before"].(time.Time); !ok || !got.Equal(notBefore) {
		t.Fatalf("not_before should stay a time.Time: %#v", data["not_before"])
	}

	var response map[string]interface{}
	if err := json.Unmarshal([]byte(data["response"].(string)), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	responseFP, ok := response["fingerprint_hash"].(map[string]interface{})
	if !ok || responseFP["sha256"] != fp.SHA256 {
		t.Fatalf("response JSON missing fingerprint_hash object: %#v", response["fingerprint_hash"])
	}
	if response["not_before"] != notBefore.Format(time.RFC3339) {
		t.Fatalf("response JSON should marshal time as RFC3339: %#v", response["not_before"])
	}
}

func TestSSLExpiredDoesNotMatchNotYetValid(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		Raw:          []byte("certificate-bytes"),
		DNSNames:     []string{"one.example"},
		NotBefore:    now.Add(24 * time.Hour),
		NotAfter:     now.Add(48 * time.Hour),
		SerialNumber: big.NewInt(1),
	}
	state := &tls.ConnectionState{
		Version:          0x0304,
		CipherSuite:      0x1301,
		ServerName:       "one.example",
		PeerCertificates: []*x509.Certificate{cert},
	}
	data := map[string]interface{}{}

	(&Request{}).responseToDSLMap(data, "one.example:443", nil, state)

	if data["expired"] != false {
		t.Fatalf("not-yet-valid certificate should not be marked expired: %+v", data)
	}
}

func TestSSLProbeFailureMatchesProbeStatusFalse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("not tls\r\n"))
		_ = conn.Close()
	}()
	defer func() {
		_ = ln.Close()
		<-done
	}()

	r := newTestRequest(t, []*operators.Matcher{
		{Type: "dsl", DSL: []string{`probe_status == false`}},
	})
	result := runAgainst(t, r, ln.Addr().String())
	if result == nil || !result.Matched {
		t.Fatalf("expected probe_status=false matcher to fire, got %+v", result)
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
