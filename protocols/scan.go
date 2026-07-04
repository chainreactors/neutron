package protocols

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type ScanContext struct {
	context.Context
	// exported / configurable fields
	Input    string
	Payloads map[string]interface{}
	// callbacks or hooks
	OnError  func(error)
	OnResult func(e *InternalWrappedEvent)
	TraceAll bool
	// GlobalVars holds pre-computed stable variable values for this execution.
	// Random/static variables (e.g. rand_base()) and bare {{randstr}}/{{randnum}}
	// are evaluated once here so they stay identical across request blocks within
	// one scan, yet are regenerated between scans.
	GlobalVars map[string]interface{}

	// unexported state fields
	errors   []error
	warnings []string
	events   []*InternalWrappedEvent
	values   map[string]interface{}

	// might not be required but better to sync
	m sync.Mutex
}

// NewScanContext creates a new scan context using input. Each context gets its
// own CookieJar for nuclei-compatible HTTP cookie reuse, while separate
// executions stay isolated.
func NewScanContext(input string, payloads map[string]interface{}) *ScanContext {
	return &ScanContext{Input: input, Payloads: payloads, values: make(map[string]interface{})}
}

func (s *ScanContext) Set(key string, val interface{}) {
	s.m.Lock()
	s.values[key] = val
	s.m.Unlock()
}

func (s *ScanContext) Get(key string) (interface{}, bool) {
	s.m.Lock()
	v, ok := s.values[key]
	s.m.Unlock()
	return v, ok
}

// GenerateResult returns final results slice from all events
func (s *ScanContext) GenerateResult() []*ResultEvent {
	s.m.Lock()
	defer s.m.Unlock()
	return aggregateResults(s.events)
}

// LogEvent logs events to all events and triggeres any callbacks
func (s *ScanContext) LogEvent(e *InternalWrappedEvent) {
	s.m.Lock()
	defer s.m.Unlock()
	if e == nil {
		// do not log nil events
		return
	}
	if s.OnResult != nil {
		s.OnResult(e)
	}
	s.events = append(s.events, e)
}

// LogError logs error to all events and triggeres any callbacks
func (s *ScanContext) LogError(err error) {
	s.m.Lock()
	defer s.m.Unlock()
	if err == nil {
		return
	}

	if s.OnError != nil {
		s.OnError(err)
	}
	s.errors = append(s.errors, err)

	errorMessage := joinErrors(s.errors)
	results := aggregateResults(s.events)
	for _, result := range results {
		result.Error = errorMessage
	}
	for _, e := range s.events {
		e.InternalEvent["error"] = errorMessage
	}
}

// LogWarning logs warning to all events
func (s *ScanContext) LogWarning(format string, args ...interface{}) {
	s.m.Lock()
	defer s.m.Unlock()
	val := fmt.Sprintf(format, args...)
	s.warnings = append(s.warnings, val)

	for _, e := range s.events {
		if e.InternalEvent != nil {
			e.InternalEvent["warning"] = strings.Join(s.warnings, "; ")
		}
	}
}

// aggregateResults aggregates results from multiple events
func aggregateResults(events []*InternalWrappedEvent) []*ResultEvent {
	var results []*ResultEvent
	for _, e := range events {
		results = append(results, e.Results...)
	}
	return results
}

// joinErrors joins multiple errors and returns a single error string
func joinErrors(errors []error) string {
	var errorMessages []string
	for _, e := range errors {
		if e != nil {
			errorMessages = append(errorMessages, e.Error())
		}
	}
	return strings.Join(errorMessages, "; ")
}
