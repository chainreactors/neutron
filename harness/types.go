package harness

import (
	"net/http"
	"regexp"
	"time"

	"github.com/chainreactors/neutron/convert"
)

const (
	StatusOK           = "ok"
	StatusDivergent    = "divergent"
	StatusUnsupported  = "unsupported"
	StatusConvertError = "convert_error"
	StatusCompileError = "compile_error"
	StatusExecuteError = "execute_error"
	DefaultMaxDelay    = 10 * time.Second

	latencyLowerBoundMargin = 250 * time.Millisecond
)

type Options struct {
	MaxDelay time.Duration
}

type VerifyOptions struct {
	Options
	Workers int
	Debug   bool
}

type POCFile struct {
	Path string
	Data []byte
	POC  *convert.XrayPOC
}

type Scenario struct {
	Name        string
	Rules       []string
	Routes      []*Route
	Variables   map[string]string
	Unsupported []string
}

func (s *Scenario) Supported() bool {
	return s != nil && len(s.Unsupported) == 0 && len(s.Routes) > 0
}

type Route struct {
	Rule         string
	Method       string
	PathTemplate string
	Path         *Pattern
	Body         *Pattern
	Headers      map[string]*Pattern
	Response     *ResponseSpec
	Build        func(map[string]string) (*ResponseSpec, map[string]string)
	hits         int
}

type Pattern struct {
	Re     *regexp.Regexp
	Groups map[string]string
}

type ResponseSpec struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	Delay      time.Duration
	Variables  map[string]string
}

func newResponseSpec() *ResponseSpec {
	return &ResponseSpec{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
		},
		Body: "",
		Variables: map[string]string{
			"randstr": "harness",
			"randnum": "1234",
		},
	}
}

type FileReport struct {
	Path               string   `json:"path"`
	Name               string   `json:"name,omitempty"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason,omitempty"`
	Matched            bool     `json:"matched"`
	Scenarios          int      `json:"scenarios"`
	SupportedScenarios int      `json:"supported_scenarios"`
	Requests           int      `json:"requests,omitempty"`
	Unsupported        []string `json:"unsupported,omitempty"`
	Debug              []Trace  `json:"debug,omitempty"`
}

type Trace struct {
	Scenario string              `json:"scenario,omitempty"`
	Event    int                 `json:"event"`
	Matched  bool                `json:"matched"`
	Extracts map[string][]string `json:"extracts,omitempty"`
	Dynamic  map[string][]string `json:"dynamic,omitempty"`
	Data     map[string]string   `json:"data,omitempty"`
}

type VerifyReport struct {
	Total        int          `json:"total"`
	OK           int          `json:"ok"`
	Divergent    int          `json:"divergent"`
	Unsupported  int          `json:"unsupported"`
	ConvertError int          `json:"convert_error"`
	CompileError int          `json:"compile_error"`
	ExecuteError int          `json:"execute_error"`
	Files        []FileReport `json:"files"`
}

func (r *VerifyReport) add(fr FileReport) {
	r.Files = append(r.Files, fr)
	r.Total++
	switch fr.Status {
	case StatusOK:
		r.OK++
	case StatusDivergent:
		r.Divergent++
	case StatusUnsupported:
		r.Unsupported++
	case StatusConvertError:
		r.ConvertError++
	case StatusCompileError:
		r.CompileError++
	case StatusExecuteError:
		r.ExecuteError++
	}
}
