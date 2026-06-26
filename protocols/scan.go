package protocols

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type ScanContext struct {
	context.Context
	// exported / configurable fields
	Input    string
	Payloads map[string]interface{}
	// Transport, when non-nil, overrides the per-request HTTP transport for this
	// execution only. The request's compiled http.Client (CheckRedirect, Jar,
	// Timeout, ...) is preserved via a shallow clone; only the RoundTripper is
	// swapped. Active-match engines should prefer this over Client — replacing
	// the whole client drops the template's `redirects:` policy and silently
	// turns `redirects: false` templates into follow-302 templates.
	Transport http.RoundTripper
	// CookieJar is a per-execution cookie jar used by HTTP requests unless
	// disable-cookie is set on the request. NewScanContext creates one
	// automatically so templates can share cookies within one execution while
	// separate scan executions stay isolated, matching nuclei's contextargs
	// pattern.
	CookieJar http.CookieJar
	// Client, when non-nil, overrides the per-request default HTTP client for
	// this execution only. It lets active-match engines inject a client/transport
	// without mutating the shared, compiled template (which is concurrency-unsafe).
	// nil = use the request's own compiled client.
	//
	// Deprecated: prefer Transport. Setting Client wholesale replaces the
	// compiled http.Client and discards CheckRedirect/Jar/Timeout — templates
	// with `redirects: false` then silently follow 302s and lose Location-header
	// matches. Retained only for backward compatibility; Transport takes
	// precedence when both are set.
	Client *http.Client
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

	// might not be required but better to sync
	m sync.Mutex
}

// NewScanContext creates a new scan context using input. Each context gets its
// own CookieJar for nuclei-compatible HTTP cookie reuse, while separate
// executions stay isolated.
func NewScanContext(input string, payloads map[string]interface{}) *ScanContext {
	ctx := &ScanContext{Input: input, Payloads: payloads}
	ctx.CookieJar = newCookieJar()
	return ctx
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

type cookieJar struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie
}

func newCookieJar() http.CookieJar {
	return &cookieJar{cookies: make(map[string][]*http.Cookie)}
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	host := u.Host
	existing := j.cookies[host]
	for _, c := range cookies {
		found := false
		for i, e := range existing {
			if e.Name == c.Name {
				existing[i] = c
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, c)
		}
	}
	j.cookies[host] = existing
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies[u.Host]
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
