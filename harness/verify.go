package harness

import (
	"fmt"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainreactors/neutron/convert"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

var waitForCallRE = regexp.MustCompile(`wait_for\([^)]*\)`)

func Verify(input string, opts VerifyOptions) (*VerifyReport, error) {
	files, err := Load(input)
	if err != nil {
		return nil, err
	}
	if opts.Workers <= 0 {
		opts.Workers = 1
	}

	jobs := make(chan *POCFile)
	results := make(chan FileReport, len(files))
	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				results <- VerifyFile(file, opts)
			}
		}()
	}
	for _, file := range files {
		jobs <- file
	}
	close(jobs)
	wg.Wait()
	close(results)

	var reports []FileReport
	for report := range results {
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Path < reports[j].Path })

	out := &VerifyReport{}
	for _, report := range reports {
		out.add(report)
	}
	return out, nil
}

func VerifyFile(file *POCFile, opts VerifyOptions) FileReport {
	report := FileReport{
		Path: file.Path,
	}
	if file.POC != nil {
		report.Name = file.POC.Name
	}
	scenarioOptions := opts.Options
	if scenarioOptions.MaxDelay == 0 {
		scenarioOptions.MaxDelay = DefaultMaxDelay
	}

	scenarios, err := BuildScenarios(file.POC, scenarioOptions)
	if err != nil {
		report.Status = StatusUnsupported
		report.Reason = err.Error()
		return report
	}
	report.Scenarios = len(scenarios)
	for _, scenario := range scenarios {
		if scenario.Supported() {
			report.SupportedScenarios++
		} else {
			report.Unsupported = append(report.Unsupported, scenario.Unsupported...)
		}
	}
	report.Unsupported = uniqueStrings(report.Unsupported)

	converted, err := convert.Convert(file.Data)
	if err != nil {
		report.Status = StatusConvertError
		report.Reason = err.Error()
		return report
	}
	converted = neutralizeWaitFor(converted)
	var tmpl templates.Template
	if err := yaml.Unmarshal(converted, &tmpl); err != nil {
		report.Status = StatusCompileError
		report.Reason = err.Error()
		return report
	}
	compileOptions := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: requestTimeoutSeconds(scenarioOptions.MaxDelay)}}
	if err := tmpl.Compile(compileOptions); err != nil {
		report.Status = StatusCompileError
		report.Reason = err.Error()
		return report
	}
	report.Requests = tmpl.TotalRequests

	if report.SupportedScenarios == 0 {
		report.Status = StatusUnsupported
		if report.Reason == "" {
			report.Reason = "no supported generated scenario"
		}
		return report
	}

	for _, scenario := range scenarios {
		if !scenario.Supported() {
			continue
		}
		server := httptest.NewServer(NewScenarioServer(scenario).Handler())
		result, traces, execErr := executeTemplate(&tmpl, server.URL, scenario.Name, opts.Debug)
		server.CloseClientConnections()
		server.Close()
		if opts.Debug {
			report.Debug = append(report.Debug, traces...)
		}
		if execErr != nil {
			report.Status = StatusExecuteError
			report.Reason = execErr.Error()
			return report
		}
		if result != nil && result.Matched {
			report.Status = StatusOK
			report.Matched = true
			return report
		}
	}

	report.Status = StatusDivergent
	report.Reason = "converted neutron template did not match any generated xray-positive scenario"
	return report
}

func executeTemplate(tmpl *templates.Template, target, scenario string, debug bool) (*operators.Result, []Trace, error) {
	if !debug {
		result, err := tmpl.Execute(target, nil)
		return result, nil, err
	}
	ctx := protocols.NewScanContext(target, nil)
	ctx.TraceAll = true
	traces := []Trace{}
	ctx.OnResult = func(event *protocols.InternalWrappedEvent) {
		traces = append(traces, summarizeTrace(scenario, len(traces)+1, event))
	}
	result, err := tmpl.Executor.Execute(ctx)
	return result, traces, err
}

func summarizeTrace(scenario string, index int, event *protocols.InternalWrappedEvent) Trace {
	trace := Trace{
		Scenario: scenario,
		Event:    index,
		Data:     map[string]string{},
	}
	if event == nil {
		return trace
	}
	if event.OperatorsResult != nil {
		trace.Matched = event.OperatorsResult.Matched
		trace.Extracts = event.OperatorsResult.Extracts
		trace.Dynamic = event.OperatorsResult.DynamicValues
	}
	for _, key := range []string{
		"status_code", "latency", "duration", "body", "content_type", "header", "all_headers",
		"path", "request", "matched", "r0latency", "r1latency",
		"s1", "s2", "s3", "s4", "rfilename", "randstr", "randomstr", "randStr1", "randStr1_hex", "random_filename",
		"status_code_0", "status_code_1", "status_code_2", "status_code_3", "status_code_4", "body_0", "body_1", "body_2", "body_3", "body_4",
	} {
		if value, ok := event.InternalEvent[key]; ok {
			trace.Data[key] = traceValue(value)
		}
	}
	return trace
}

func traceValue(value interface{}) string {
	out := fmt.Sprint(value)
	out = strings.ReplaceAll(out, "\r\n", "\\r\\n")
	out = strings.ReplaceAll(out, "\n", "\\n")
	if len(out) > 240 {
		return out[:240] + "..."
	}
	return out
}

func requestTimeoutSeconds(maxDelay time.Duration) int {
	timeout := int(maxDelay/time.Second) + 3
	if timeout < 5 {
		return 5
	}
	return timeout
}

func neutralizeWaitFor(converted []byte) []byte {
	return []byte(neutralizeWaitForDSL(string(converted)))
}

func neutralizeWaitForDSL(expr string) string {
	return waitForCallRE.ReplaceAllString(expr, "true")
}
