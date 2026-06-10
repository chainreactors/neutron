// Package ssl implements a native, standard-library-only TLS/certificate
// inspection protocol, modeled after nuclei's `ssl` protocol. It performs a
// single TLS handshake (no HTTP request) against the target and exposes the
// peer certificate as nuclei-compatible DSL keys (subject_cn, issuer_org,
// serial, fingerprint_hash, tls_version, cipher, ...) for matchers/extractors.
//
// Scope: this package never imports zcrypto/ztls. Nuclei reaches for zcrypto
// via tlsx when it needs to talk SSLv3, export ciphers, or other pre-TLS-1.2
// oddities that Go's crypto/tls dropped in 1.22+. We deliberately accept that
// limit — running probes against legitimately-modern endpoints covers the DSL
// surface used by ~all nuclei `ssl/` templates, and adding zcrypto would more
// than triple the dependency closure. When `min_version` pins TLS 1.1 or
// below we DO opt into `tls.InsecureCipherSuites()` so the CBC/3DES suites
// the stdlib still ships keep working; SSLv3 / RC4_EXPORT / DES40 endpoints
// fall outside this package's reach. For those, fall back to the upstream
// tlsx/nuclei binaries.
package ssl

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/common/tlsx"
)

// Request contains an SSL protocol request to be made from a template.
type Request struct {
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// Address is the host:port target to connect to. Supports template variables
	// such as {{Host}}:{{Port}}. When empty, the scan input is used.
	Address string `json:"address,omitempty" yaml:"address,omitempty"`

	// MinVersion / MaxVersion bound the negotiated TLS version. Accepted values:
	// sslv3, tls10, tls11, tls12, tls13. Empty means library default.
	MinVersion string `json:"min_version,omitempty" yaml:"min_version,omitempty"`
	MaxVersion string `json:"max_version,omitempty" yaml:"max_version,omitempty"`

	// CipherSuites optionally pins the offered TLS <=1.2 cipher suites by IANA
	// name (for example TLS_RSA_WITH_AES_128_CBC_SHA). TLS 1.3 suites are not
	// configurable through crypto/tls.
	CipherSuites []string `json:"cipher_suites,omitempty" yaml:"cipher_suites,omitempty"`

	// The following nuclei ssl options require enumeration behavior or ztls.
	// They are declared so YAML cannot silently ignore them; Compile rejects
	// unsupported non-zero values with a clear error.
	ScanMode       string `json:"scan_mode,omitempty" yaml:"scan_mode,omitempty"`
	TLSVersionEnum bool   `json:"tls_version_enum,omitempty" yaml:"tls_version_enum,omitempty"`
	TLSCipherEnum  bool   `json:"tls_cipher_enum,omitempty" yaml:"tls_cipher_enum,omitempty"`
	TLSCipherTypes bool   `json:"tls_cipher_types,omitempty" yaml:"tls_cipher_types,omitempty"`

	operators.Operators `json:",inline,omitempty" yaml:",inline,omitempty"`

	CompiledOperators *operators.Operators       `json:"-" yaml:"-" jsonschema:"-"`
	dialer            *net.Dialer                `json:"-" yaml:"-" jsonschema:"-"`
	options           *protocols.ExecuterOptions `json:"-" yaml:"-" jsonschema:"-"`
	cipherSuites      []uint16                   `json:"-" yaml:"-" jsonschema:"-"`
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options
	if err := r.validateOptions(); err != nil {
		return err
	}

	timeout := 5
	if options != nil && options.Options != nil && options.Options.Timeout > 0 {
		timeout = options.Options.Timeout
	}
	r.dialer = &net.Dialer{
		Timeout:   time.Duration(timeout) * time.Second,
		KeepAlive: 3 * time.Second,
	}

	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return err
		}
		r.CompiledOperators = compiled
	}
	return nil
}

func (r *Request) validateOptions() error {
	if r == nil {
		return fmt.Errorf("ssl request is nil")
	}
	var unsupported []string
	if r.TLSVersionEnum {
		unsupported = append(unsupported, "tls_version_enum")
	}
	if r.TLSCipherEnum {
		unsupported = append(unsupported, "tls_cipher_enum")
	}
	if r.TLSCipherTypes {
		unsupported = append(unsupported, "tls_cipher_types")
	}
	if mode := strings.TrimSpace(r.ScanMode); mode != "" && !strings.EqualFold(mode, "ctls") {
		unsupported = append(unsupported, "scan_mode="+mode)
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("unsupported nuclei ssl option(s): %s; neutron stdlib ssl supports address, min_version, max_version, scan_mode: ctls, and cipher_suites", strings.Join(unsupported, ", "))
	}
	if r.referencesRevoked() && !tlsx.HasRevokeCheck() {
		return fmt.Errorf("ssl request references revoked but no revocation backend is registered; import _ \"github.com/chainreactors/neutron/common/tlsx/full\" in the scanner binary")
	}
	if len(r.CipherSuites) == 0 {
		r.cipherSuites = nil
		return nil
	}
	ids, err := parseCipherSuiteIDs(r.CipherSuites)
	if err != nil {
		return err
	}
	r.cipherSuites = ids
	return nil
}

func (r *Request) referencesRevoked() bool {
	for _, matcher := range r.Matchers {
		if matcher == nil {
			continue
		}
		if matcher.Part == "revoked" {
			return true
		}
		for _, expr := range matcher.DSL {
			if containsIdent(expr, "revoked") {
				return true
			}
		}
	}
	for _, extractor := range r.Extractors {
		if extractor == nil {
			continue
		}
		if extractor.Part == "revoked" {
			return true
		}
		for _, expr := range extractor.DSL {
			if containsIdent(expr, "revoked") {
				return true
			}
		}
	}
	return false
}

func containsIdent(expr, ident string) bool {
	for i := 0; i < len(expr); {
		c := expr[i]
		if !isIdentByte(c) {
			i++
			continue
		}
		start := i
		for i < len(expr) && isIdentByte(expr[i]) {
			i++
		}
		if expr[start:i] == ident {
			return true
		}
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// Requests returns the total number of requests the rule will perform.
func (r *Request) Requests() int {
	return 1
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}
