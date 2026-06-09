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
	"net"
	"time"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
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

	operators.Operators `json:",inline,omitempty" yaml:",inline,omitempty"`

	CompiledOperators *operators.Operators       `json:"-" yaml:"-" jsonschema:"-"`
	dialer            *net.Dialer                `json:"-" yaml:"-" jsonschema:"-"`
	options           *protocols.ExecuterOptions `json:"-" yaml:"-" jsonschema:"-"`
}

// Compile compiles the protocol request for further execution.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options

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

func (r *Request) CompileOperators() error {
	compiled := &r.Operators
	if err := compiled.Compile(); err != nil {
		return err
	}
	r.CompiledOperators = compiled
	return nil
}

// Requests returns the total number of requests the rule will perform.
func (r *Request) Requests() int {
	return 1
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}
