package ssl

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/tlsx"
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

// Match dispatches through protocols.MakeDefaultMatchFunc — the shared matrix
// covers size/words/regex/binary/dsl and falls through to MatchWithHandler for
// json/xpath, so this protocol stays aligned with nuclei's ssl by construction
// (one matrix, no per-protocol switch to forget). The partResolver carries the
// ssl-specific body/all→response fold that xray-converter templates rely on.
func (r *Request) Match(data map[string]interface{}, matcher *operators.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFunc(data, matcher, func(part string) (string, bool) {
		return r.getMatchPart(part, data)
	})
}

// Extract dispatches through protocols.MakeDefaultExtractFunc; see Match for
// rationale.
func (r *Request) Extract(data map[string]interface{}, extractor *operators.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFunc(data, extractor, func(part string) (string, bool) {
		return r.getMatchPart(part, data)
	})
}

// ExecuteWithResults connects to each target, performs the TLS handshake and
// runs the operators against the certificate data.
//
// Handshake/dial errors are deliberately swallowed: each ssl request block is
// an independent probe (TLS templates routinely fan out across tls10/tls11/
// tls12/tls13 sub-requests, where 3 out of 4 are expected to fail on any
// given server). Propagating the error would abort the remaining sub-requests
// inside the same executer loop, defeating templates like nuclei's
// deprecated-tls / weak-cipher-suites / insecure-cipher-suite-detect. The
// probe is still observable: a synthetic event with probe_status=false is
// emitted so DSL matchers and the caller's LogEvent see the miss.
func (r *Request) ExecuteWithResults(input *protocols.ScanContext, dynamicValues, previous map[string]interface{}, callback protocols.OutputEventCallback) error {
	var globalVars map[string]interface{}
	var scanInput string
	if input != nil {
		globalVars = input.GlobalVars
		scanInput = input.Input
	}

	target := r.resolveTarget(scanInput, common.MergeMaps(globalVars, dynamicValues))
	if err := r.executeTarget(input, target, dynamicValues, previous, callback); err != nil {
		// Emit a probe_status=false event so the executer sees something for
		// this sub-request — matchers/extractors that key off probe_status
		// can still fire, and the next sub-request gets a chance to run.
		host, port := splitHostPort(target)
		data := map[string]interface{}{
			"host":         host,
			"port":         port,
			"matched":      target,
			"type":         r.Type().String(),
			"probe_status": false,
			"error":        err.Error(),
		}
		for k, v := range previous {
			data[k] = v
		}
		for k, v := range dynamicValues {
			data[k] = v
		}
		if encoded, marshalErr := json.Marshal(map[string]interface{}{
			"host":         host,
			"port":         port,
			"matched":      target,
			"probe_status": false,
			"error":        err.Error(),
		}); marshalErr == nil {
			data["response"] = string(encoded)
		}
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
	}
	return nil
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
	// When the template explicitly pins a TLS version, widen the cipher list.
	// Two distinct reasons:
	//   - TLS 1.1 and below: Go 1.22+ removed most CBC/3DES/RC4 suites from
	//     `tls.CipherSuites()`. Without `InsecureCipherSuites()` we can't even
	//     finish a handshake against legacy servers, defeating deprecated-tls
	//     and weak-cipher-suites templates.
	//   - TLS 1.2 pinned: the insecure-cipher-suite-detect template enumerates
	//     RC4/NULL/EXPORT suites on 1.2 servers — we need the same widening
	//     so we can actually negotiate them when the target offers them.
	// We DON'T widen when no version is pinned at all (default modern probe):
	// the default behavior should match a normal HTTPS client.
	if len(r.cipherSuites) > 0 {
		cfg.CipherSuites = append([]uint16(nil), r.cipherSuites...)
	} else if cfg.MinVersion != 0 || cfg.MaxVersion != 0 {
		cfg.CipherSuites = append(cfg.CipherSuites, allCipherSuiteIDs()...)
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

// responseToDSLMap flattens the leaf certificate and handshake state into DSL
// keys. Certificate/handshake extraction (both xray cert_* and nuclei style) is
// delegated to tlsx so the HTTP and SSL paths stay in lockstep; this method only
// adds the ssl-protocol connection metadata and the `response` JSON summary.
func (r *Request) responseToDSLMap(data map[string]interface{}, target string, conn *tls.Conn, state *tls.ConnectionState) {
	host, port := splitHostPort(target)
	sni := state.ServerName
	if sni == "" {
		sni = host
	}

	// xray cert_* + nuclei style keys + raw_cert.
	tlsx.FillCertDSL(data, state, sni)

	// Connection-level metadata specific to the ssl protocol.
	data["host"] = host
	data["port"] = port
	data["matched"] = target
	data["type"] = r.Type().String()

	var ip string
	if conn != nil {
		if addr := conn.RemoteAddr(); addr != nil {
			if got, _, err := net.SplitHostPort(addr.String()); err == nil {
				ip = got
				data["ip"] = ip
			}
		}
	}

	// response: a JSON summary so `part: response` and DSL over the whole
	// structure work, matching nuclei's default behaviour. Built from the nuclei
	// field set plus connection metadata — never the binary raw_cert DER.
	summary := tlsx.NucleiCertFields(state, sni)
	if summary == nil {
		summary = map[string]interface{}{}
	}
	summary["host"] = host
	summary["port"] = port
	summary["matched"] = target
	if ip != "" {
		summary["ip"] = ip
	}
	if encoded, err := json.Marshal(summary); err == nil {
		data["response"] = string(encoded)
	}
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

// certificateFingerprintHash is kept as an alias of the shared tlsx type so the
// `fingerprint_hash` DSL value has a stable, package-local name.
type certificateFingerprintHash = tlsx.FingerprintHash

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

func parseCipherSuiteIDs(names []string) ([]uint16, error) {
	ids := make([]uint16, 0, len(names))
	seen := map[uint16]struct{}{}
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		id, ok := cipherSuiteID(name)
		if !ok {
			return nil, fmt.Errorf("unsupported tls cipher suite %q", raw)
		}
		if isTLS13CipherSuite(id) {
			return nil, fmt.Errorf("tls 1.3 cipher suite %q is not configurable by crypto/tls CipherSuites", raw)
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("cipher_suites must contain at least one supported suite")
	}
	return ids, nil
}

func isTLS13CipherSuite(id uint16) bool {
	return id >= 0x1301 && id <= 0x1305
}
