package ssl

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request.
func (r *Request) Type() protocols.ProtocolType {
	return protocols.SSLProtocol
}

func (r *Request) getMatchPart(part string, data protocols.InternalEvent) (string, bool) {
	switch part {
	case "", "body", "all":
		part = "response"
	}
	item, ok := data[part]
	if !ok {
		return "", false
	}
	return common.ToString(item), true
}

// Match matches a generic data response against a given matcher.
func (r *Request) Match(data map[string]interface{}, matcher *operators.Matcher) (bool, []string) {
	if matcher.GetType() == operators.DSLMatcher {
		return matcher.Result(matcher.MatchDSL(data)), nil
	}
	itemStr, ok := r.getMatchPart(matcher.Part, data)
	if !ok {
		return false, []string{}
	}
	switch matcher.GetType() {
	case operators.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr))), []string{}
	case operators.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(itemStr, data))
	case operators.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(itemStr))
	case operators.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(itemStr))
	default:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWithHandler(itemStr, data))
	}
	return false, []string{}
}

// Extract performs an extracting operation for an extractor on data.
func (r *Request) Extract(data map[string]interface{}, extractor *operators.Extractor) map[string]struct{} {
	item, ok := r.getMatchPart(extractor.Part, data)
	if !ok && extractor.GetType() != operators.DSLExtractor {
		return nil
	}
	switch extractor.GetType() {
	case operators.RegexExtractor:
		return extractor.ExtractRegex(item)
	case operators.KValExtractor:
		return extractor.ExtractKval(data)
	case operators.DSLExtractor:
		return extractor.ExtractDSL(data)
	default:
		return extractor.ExtractWithHandler(item, data)
	}
	return nil
}

// ExecuteWithResults connects to each target, performs the TLS handshake and
// runs the operators against the certificate data.
func (r *Request) ExecuteWithResults(input *protocols.ScanContext, dynamicValues, previous map[string]interface{}, callback protocols.OutputEventCallback) error {
	var globalVars map[string]interface{}
	var scanInput string
	if input != nil {
		globalVars = input.GlobalVars
		scanInput = input.Input
	}

	target := r.resolveTarget(scanInput, common.MergeMaps(globalVars, dynamicValues))
	return r.executeTarget(input, target, dynamicValues, previous, callback)
}

func (r *Request) resolveTarget(input string, vars map[string]interface{}) string {
	host, port := splitHostPort(input)
	hostname := host
	if host != "" && port != "" {
		hostname = net.JoinHostPort(host, port)
	}
	targetVars := map[string]interface{}{
		"Host":     host,
		"Hostname": hostname,
		"Port":     port,
		"BaseURL":  input,
		"RootURL":  hostname,
	}
	merged := common.MergeMaps(vars, targetVars)

	address := strings.TrimSpace(r.Address)
	if address == "" {
		return normalizeTarget(input)
	}
	resolved := common.Replace(address, merged)
	return normalizeTarget(resolved)
}

func (r *Request) executeTarget(input *protocols.ScanContext, target string, dynamicValues, previous map[string]interface{}, callback protocols.OutputEventCallback) error {
	host, _ := splitHostPort(target)

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	if v := tlsVersionValue(r.MinVersion); v != 0 {
		cfg.MinVersion = v
	}
	if v := tlsVersionValue(r.MaxVersion); v != 0 {
		cfg.MaxVersion = v
	}

	conn, err := r.dialTLS(target, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates presented by %s", target)
	}

	data := make(map[string]interface{})
	for k, v := range previous {
		data[k] = v
	}
	for k, v := range dynamicValues {
		data[k] = v
	}
	r.responseToDSLMap(data, target, conn, &state)

	event := &protocols.InternalWrappedEvent{InternalEvent: data}
	if r.CompiledOperators != nil {
		result, ok := r.CompiledOperators.Execute(data, r.Match, r.Extract)
		if ok && result != nil {
			result.PayloadValues = dynamicValues
			event.OperatorsResult = result
			event.Results = r.MakeResultEvent(event)
		}
	}
	callback(event)
	return nil
}

func (r *Request) dialTLS(target string, cfg *tls.Config) (*tls.Conn, error) {
	// Honour an injected dialer (e.g. proxy) by dialing TCP first, then doing
	// the TLS handshake on top of it.
	if r.options != nil && r.options.Options != nil && r.options.Options.DialContext != nil {
		raw, err := r.options.Options.DialContext(context.Background(), "tcp", target)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, cfg)
		_ = conn.SetDeadline(time.Now().Add(r.dialer.Timeout))
		if err := conn.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
	return tls.DialWithDialer(r.dialer, "tcp", target, cfg)
}

// responseToDSLMap flattens the leaf certificate and handshake state into
// nuclei-compatible DSL keys.
func (r *Request) responseToDSLMap(data map[string]interface{}, target string, conn *tls.Conn, state *tls.ConnectionState) {
	leaf := state.PeerCertificates[0]
	host, port := splitHostPort(target)
	sni := state.ServerName
	if sni == "" {
		sni = host
	}
	certNames := certificateNames(leaf)
	serial := formatSerial(leaf)
	fingerprint := certificateFingerprintHash{
		MD5:    certFingerprint(leaf, "md5"),
		SHA1:   certFingerprint(leaf, "sha1"),
		SHA256: certFingerprint(leaf, "sha256"),
	}

	// `revoked` is intentionally omitted: it needs OCSP/CRL fetching, which the
	// stdlib-only handshake path does not do.
	expired := time.Now().After(leaf.NotAfter)
	mismatched := isMismatchedCert(sni, certNames)

	flat := map[string]interface{}{
		"host":         host,
		"port":         port,
		"matched":      target,
		"probe_status": true,
		// neutron always handshakes with crypto/tls, which tlsx labels "ctls";
		// emit the engine name (string) to match nuclei rather than a bare bool.
		"tls_connection":       "ctls",
		"sni":                  sni,
		"subject_cn":           leaf.Subject.CommonName,
		"subject_an":           leaf.DNSNames,
		"domains":              uniqueDomains(certNames),
		"subject_dn":           leaf.Subject.String(),
		"subject_org":          leaf.Subject.Organization,
		"issuer_cn":            leaf.Issuer.CommonName,
		"issuer_dn":            leaf.Issuer.String(),
		"issuer_org":           leaf.Issuer.Organization,
		"emails":               leaf.EmailAddresses,
		"serial":               serial,
		"not_before":           leaf.NotBefore,
		"not_after":            leaf.NotAfter,
		"tls_version":          tlsVersionName(state.Version),
		"cipher":               cipherName(state.CipherSuite),
		"fingerprint_hash":     fingerprint,
		"wildcard_certificate": isWildcardName(certNames),
		"self_signed":          isSelfSigned(leaf),
		"expired":              expired,
		"mismatched":           mismatched,
	}
	for k, v := range flat {
		data[k] = v
	}

	if conn != nil {
		if addr := conn.RemoteAddr(); addr != nil {
			if ip, _, err := net.SplitHostPort(addr.String()); err == nil {
				flat["ip"] = ip
				data["ip"] = ip
			}
		}
	}

	// raw_cert: whole presented chain as concatenated DER, for xray-style
	// bcontains(raw_cert, ...) matching.
	var raw strings.Builder
	for _, cert := range state.PeerCertificates {
		raw.Write(cert.Raw)
	}
	data[common.RawCertKey] = raw.String()

	// response: a JSON summary so `part: response` and DSL over the whole
	// structure work, matching nuclei's default behaviour.
	if encoded, err := json.Marshal(flat); err == nil {
		data["response"] = string(encoded)
	}
	data["type"] = r.Type().String()
}

// MakeResultEvent creates a result event from an internal wrapped event.
func (r *Request) MakeResultEvent(wrapped *protocols.InternalWrappedEvent) []*protocols.ResultEvent {
	return protocols.MakeDefaultResultEvent(r, wrapped)
}

func (r *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{r.CompiledOperators}
}

func (r *Request) MakeResultEventItem(wrapped *protocols.InternalWrappedEvent) *protocols.ResultEvent {
	data := &protocols.ResultEvent{
		TemplateID:       common.ToString(wrapped.InternalEvent["template-id"]),
		Type:             common.ToString(wrapped.InternalEvent["type"]),
		Host:             common.ToString(wrapped.InternalEvent["host"]),
		Matched:          common.ToString(wrapped.InternalEvent["matched"]),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		Timestamp:        time.Now(),
		IP:               common.ToString(wrapped.InternalEvent["ip"]),
	}
	return data
}

// --- helpers -------------------------------------------------------------

func normalizeTarget(target string) string {
	host, port := splitHostPort(target)
	if host == "" {
		return strings.TrimSpace(target)
	}
	return net.JoinHostPort(host, port)
}

func splitHostPort(target string) (string, string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "443"
	}
	if strings.Contains(target, "://") || strings.HasPrefix(target, "//") {
		if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
			return splitAuthority(parsed.Host, defaultPortForScheme(parsed.Scheme))
		}
	}
	if i := strings.IndexAny(target, "/?#"); i >= 0 {
		target = target[:i]
	}
	return splitAuthority(target, "443")
}

func splitAuthority(authority, defaultPort string) (string, string) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", defaultPort
	}
	if host, port, err := net.SplitHostPort(authority); err == nil {
		if port == "" {
			port = defaultPort
		}
		return host, port
	}
	if strings.HasPrefix(authority, "[") {
		if end := strings.Index(authority, "]"); end > 0 {
			return authority[1:end], defaultPort
		}
	}
	if strings.Count(authority, ":") == 1 {
		parts := strings.SplitN(authority, ":", 2)
		if parts[1] != "" {
			return parts[0], parts[1]
		}
		return parts[0], defaultPort
	}
	return authority, defaultPort
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return "80"
	default:
		return "443"
	}
}

func formatSerial(cert *x509.Certificate) string {
	if cert.SerialNumber == nil {
		return ""
	}
	b := cert.SerialNumber.Bytes()
	if len(b) == 0 {
		return "00"
	}
	parts := make([]string, len(b))
	for i, by := range b {
		parts[i] = fmt.Sprintf("%02X", by)
	}
	return strings.Join(parts, ":")
}

func certFingerprint(cert *x509.Certificate, algo string) string {
	switch algo {
	case "md5":
		sum := md5.Sum(cert.Raw)
		return hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum(cert.Raw)
		return hex.EncodeToString(sum[:])
	default:
		sum := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(sum[:])
	}
}

type certificateFingerprintHash struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

func certificateNames(cert *x509.Certificate) []string {
	names := make([]string, 0, 1+len(cert.DNSNames))
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	return names
}

func uniqueDomains(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	var domains []string
	for _, name := range names {
		domain := strings.TrimPrefix(name, "*.")
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains
}

func isWildcardName(names []string) bool {
	for _, name := range names {
		if strings.Contains(name, "*.") {
			return true
		}
	}
	return false
}

func isSelfSigned(cert *x509.Certificate) bool {
	return len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId)
}

func isMismatchedCert(host string, alternativeNames []string) bool {
	hostTokens := strings.Split(host, ".")
	for _, alternativeName := range alternativeNames {
		if !strings.Contains(alternativeName, "*") {
			if strings.EqualFold(alternativeName, host) {
				return false
			}
			continue
		}

		nameTokens := strings.Split(alternativeName, ".")
		if len(hostTokens) != len(nameTokens) {
			continue
		}
		matched := false
		for i, token := range nameTokens {
			if i == 0 {
				matched = matchWildcardToken(token, hostTokens[i])
			} else {
				matched = strings.EqualFold(token, hostTokens[i])
			}
			if !matched {
				break
			}
		}
		if matched {
			return false
		}
	}
	return true
}

func matchWildcardToken(name, host string) bool {
	if !strings.Contains(name, "*") {
		return strings.EqualFold(name, host)
	}
	parts := strings.Split(name, "*")
	if strings.HasPrefix(name, "*") {
		return len(parts) > 1 && strings.HasSuffix(host, parts[1])
	}
	if strings.HasSuffix(name, "*") {
		return len(parts) > 0 && strings.HasPrefix(host, parts[0])
	}
	return len(parts) > 1 && strings.HasPrefix(host, parts[0]) && strings.HasSuffix(host, parts[1])
}

// tlsVersionValue maps a textual version to the crypto/tls constant. Literal
// hex values keep this go1.11-safe (tls.VersionTLS13 was added in go1.12).
func tlsVersionValue(name string) uint16 {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sslv3", "ssl30":
		return 0x0300
	case "tls10", "tls1.0":
		return 0x0301
	case "tls11", "tls1.1":
		return 0x0302
	case "tls12", "tls1.2":
		return 0x0303
	case "tls13", "tls1.3":
		return 0x0304
	}
	return 0
}

func tlsVersionName(version uint16) string {
	switch version {
	case 0x0300:
		return "sslv3"
	case 0x0301:
		return "tls10"
	case 0x0302:
		return "tls11"
	case 0x0303:
		return "tls12"
	case 0x0304:
		return "tls13"
	}
	return fmt.Sprintf("0x%04x", version)
}

// cipherNames covers common suites by their crypto/tls constants (all present
// in go1.11). Unknown suites fall back to a hex id.
var cipherNames = map[uint16]string{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
}

func cipherName(id uint16) string {
	if name, ok := cipherNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}
