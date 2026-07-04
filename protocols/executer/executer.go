package executer

import (
	"github.com/chainreactors/utils/iutils"
	"github.com/chainreactors/neutron/common/dsl"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
)

type Executer struct {
	requests []protocols.Request
	options  *protocols.ExecuterOptions
}

type Event map[string]interface{}
type WrappedEvent struct {
	InternalEvent   Event
	OperatorsResult *operators.Result
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []protocols.Request, options *protocols.ExecuterOptions) *Executer {
	return &Executer{requests: requests, options: options}
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	for _, request := range e.requests {
		err := request.Compile(e.options)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Executer) Options() *protocols.ExecuterOptions {
	return e.options
}

// Requests returns the total number of requests the rule will perform
func (e *Executer) Requests() int {
	var count int
	for _, request := range e.requests {
		count += request.Requests()
	}
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input *protocols.ScanContext) (*operators.Result, error) {
	var result *operators.Result

	// Compute stable global variables once per execution: random/static values
	// stay identical across request blocks within a scan, regenerated between scans.
	input.GlobalVars = computeGlobalVars(e.options)

	previous := make(map[string]interface{})
	dynamicValues := iutils.MergeMaps(make(map[string]interface{}), input.Payloads)
	requestIndexOffset := 0
	for _, req := range e.requests {
		dynamicValues["__request_index_offset"] = requestIndexOffset
		err := req.ExecuteWithResults(input, dynamicValues, previous, func(event *protocols.InternalWrappedEvent) {
			if event.OperatorsResult != nil {
				for key, value := range event.OperatorsResult.DynamicValues {
					dynamicValues[key] = value
				}
				if event.OperatorsResult.Matched || event.OperatorsResult.Extracted || len(event.Results) > 0 {
					result = event.OperatorsResult
					if len(event.Results) == 0 {
						event.Results = []*protocols.ResultEvent{req.MakeResultEventItem(event)}
					}
				}
			}
			input.LogEvent(event)
		})
		if err != nil {
			return nil, err
		}
		requestIndexOffset += req.Requests()
	}
	return result, nil
}

func computeGlobalVars(options *protocols.ExecuterOptions) map[string]interface{} {
	globalVars := map[string]interface{}{
		"randstr": dsl.RandStr(8),
		"randnum": dsl.RandNum(4),
	}
	if options == nil || options.Variables.Len() == 0 {
		return globalVars
	}
	for k, v := range options.Variables.StableValues() {
		globalVars[k] = v
	}
	return globalVars
}
