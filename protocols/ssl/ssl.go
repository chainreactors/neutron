// Package ssl implements a native, standard-library-only TLS/certificate
// inspection protocol, modeled after nuclei's `ssl` protocol. It performs a
// single TLS handshake (no HTTP request) against the target and exposes the
// peer certificate as nuclei-compatible DSL keys (subject_cn, issuer_org,
// serial, fingerprint_hash, tls_version, cipher, ...) for matchers/extractors.
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

// Requests returns the total number of requests the rule will perform.
func (r *Request) Requests() int {
	return 1
}

// GetID returns the unique ID of the request if any.
func (r *Request) GetID() string {
	return r.ID
}
