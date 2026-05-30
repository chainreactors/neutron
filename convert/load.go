package convert

import (
	"gopkg.in/yaml.v3"
)

// IsXrayPOC reports whether the YAML data looks like an xray POC rather than a
// neutron/nuclei template.
//
// The two formats are mutually exclusive at the schema level: an xray POC is
// rule-oriented (top-level `rules:` plus an `expression:`), while a neutron
// template is request-oriented (`http:`/`requests:`/`network:`/`tcp:`/`udp:`).
// Detection keys off that difference — the presence of any neutron request
// block is treated as a hard negative so that already-converted templates are
// never re-converted.
//
// It is the detection half of the templates.Converter that this package
// registers; callers normally use templates.Load rather than calling this
// directly.
func IsXrayPOC(data []byte) bool {
	var probe struct {
		// neutron request blocks — any of these means it is already a template.
		HTTP     interface{} `yaml:"http"`
		Requests interface{} `yaml:"requests"`
		Network  interface{} `yaml:"network"`
		TCP      interface{} `yaml:"tcp"`
		UDP      interface{} `yaml:"udp"`

		// xray markers.
		Rules  map[string]interface{} `yaml:"rules"`
		Detail struct {
			Fingerprint interface{} `yaml:"fingerprint"`
		} `yaml:"detail"`
	}
	if yaml.Unmarshal(data, &probe) != nil {
		return false
	}
	if probe.HTTP != nil || probe.Requests != nil || probe.Network != nil ||
		probe.TCP != nil || probe.UDP != nil {
		return false
	}
	// `rules:` is the defining feature of an xray POC; `detail.fingerprint`
	// (xray fingerprint POCs) is accepted as a secondary signal.
	return len(probe.Rules) > 0 || probe.Detail.Fingerprint != nil
}
