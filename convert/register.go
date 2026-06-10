package convert

import "github.com/chainreactors/neutron/templates"

// init registers the xray converter with the templates package so that
// templates.Load transparently handles xray POCs whenever this package is
// imported (directly or via a blank import).
func init() {
	templates.RegisterConverter(xrayConverter{})
}

// xrayConverter adapts this package's xray conversion to templates.Converter.
type xrayConverter struct{}

func (xrayConverter) Name() string                        { return "xray" }
func (xrayConverter) Detect(data []byte) bool             { return IsXrayPOC(data) }
func (xrayConverter) Convert(data []byte) ([]byte, error) { return Convert(data) }
