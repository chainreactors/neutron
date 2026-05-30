package templates

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Converter recognizes a non-neutron POC format and converts it into neutron
// template YAML. Format-specific packages (e.g. the convert package for xray)
// register an implementation from their init() via RegisterConverter; Load
// consults the registered converters before falling back to parsing the input
// as a native neutron template.
//
// This is the extension point for new POC formats: add a package that produces
// neutron YAML and registers a Converter — no change to templates or to callers
// of Load is required.
type Converter interface {
	// Name identifies the source format, e.g. "xray".
	Name() string
	// Detect reports whether data is in this converter's source format.
	Detect(data []byte) bool
	// Convert transforms the source format into neutron template YAML.
	Convert(data []byte) ([]byte, error)
}

// converters holds the registered format converters, tried in registration
// order. Registration happens from package init() functions (single-threaded),
// and the slice is only read afterwards, so no locking is needed.
var converters []Converter

// RegisterConverter registers a POC-format converter. Intended to be called
// from a package init() function.
func RegisterConverter(c Converter) {
	converters = append(converters, c)
}

// DetectFormat returns the name of the first registered converter that claims
// data, or "neutron" if none does (i.e. data is treated as a native template).
func DetectFormat(data []byte) string {
	for _, c := range converters {
		if c.Detect(data) {
			return c.Name()
		}
	}
	return "neutron"
}

// Load parses data into a Template, auto-detecting the source format. Registered
// converters are tried in registration order; the first whose Detect matches is
// used to convert the input to neutron YAML. If none match, data is parsed as a
// native neutron template. The returned Template is not yet compiled.
//
// To enable a given format, import the package that registers its converter
// (e.g. blank-import github.com/chainreactors/neutron/convert for xray support).
func Load(data []byte) (*Template, error) {
	for _, c := range converters {
		if !c.Detect(data) {
			continue
		}
		converted, err := c.Convert(data)
		if err != nil {
			return nil, fmt.Errorf("convert %s poc: %w", c.Name(), err)
		}
		data = converted
		break
	}
	tmpl := &Template{}
	if err := yaml.Unmarshal(data, tmpl); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}
	return tmpl, nil
}
