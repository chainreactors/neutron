package harness

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	routes []*Route
	vars   map[string]string
	mu     sync.Mutex
}

func NewServer(scenarios []*Scenario) *Server {
	var routes []*Route
	for _, scenario := range scenarios {
		if scenario == nil || !scenario.Supported() {
			continue
		}
		routes = append(routes, scenario.Routes...)
	}
	return &Server{routes: routes, vars: map[string]string{}}
}

func NewScenarioServer(scenario *Scenario) *Server {
	return NewServer([]*Scenario{scenario})
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.ServeHTTP)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	route, captures := s.matchLocked(r)
	if route != nil {
		route.hits++
		for k, v := range captures {
			if v != "" {
				s.vars[k] = v
			}
		}
	}
	runtimeVars := cloneStringMap(s.vars)
	s.mu.Unlock()

	if route == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "neutron harness miss: %s %s", r.Method, r.URL.RequestURI())
		return
	}
	resp := route.Response
	if route.Build != nil {
		if dynamicResp, outputs := route.Build(runtimeVars); dynamicResp != nil {
			resp = dynamicResp
			s.mu.Lock()
			for k, v := range outputs {
				if v != "" {
					s.vars[k] = v
				}
			}
			s.mu.Unlock()
		}
	}
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	if resp.Delay > 0 {
		time.Sleep(resp.Delay)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write([]byte(resp.Body))
}

func (s *Server) matchLocked(r *http.Request) (*Route, map[string]string) {
	var fallback *Route
	var fallbackCaptures map[string]string
	for _, route := range s.routes {
		captures, ok := route.matches(r)
		if !ok {
			continue
		}
		if fallback == nil {
			fallback = route
			fallbackCaptures = captures
		}
		if route.hits == 0 {
			return route, captures
		}
	}
	return fallback, fallbackCaptures
}

func (r *Route) matches(req *http.Request) (map[string]string, bool) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	if strings.ToUpper(req.Method) != strings.ToUpper(method) {
		return nil, false
	}
	uri := req.URL.RequestURI()
	captures, ok := matchPath(r.Path, uri)
	if !ok {
		captures, ok = matchPath(r.Path, req.URL.Path)
	}
	if !ok {
		return nil, false
	}
	for name, pattern := range r.Headers {
		value := req.Header.Get(name)
		if strings.EqualFold(name, "host") {
			value = req.Host
		}
		headerCaptures, ok := pattern.match(value)
		if !ok {
			return nil, false
		}
		mergeCaptures(captures, headerCaptures)
	}
	if r.Body != nil {
		body, _ := readRequestBody(req)
		bodyCaptures, ok := r.Body.match(body)
		if !ok {
			bodyCaptures, ok = r.Body.match(strings.ReplaceAll(body, "\r\n", "\n"))
		}
		if !ok {
			return nil, false
		}
		mergeCaptures(captures, bodyCaptures)
	}
	return captures, true
}

func readRequestBody(req *http.Request) (string, error) {
	if req.Body == nil {
		return "", nil
	}
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	return string(data), nil
}

func matchPath(pattern *Pattern, path string) (map[string]string, bool) {
	if pattern == nil {
		return map[string]string{}, true
	}
	if captures, ok := pattern.match(path); ok {
		return captures, true
	}
	if strings.Contains(path, "%23") {
		if captures, ok := pattern.match(strings.ReplaceAll(path, "%23", "#")); ok {
			return captures, true
		}
	}
	if strings.Contains(path, "%20") {
		if captures, ok := pattern.match(strings.ReplaceAll(path, "%20", " ")); ok {
			return captures, true
		}
	}
	return pattern.match(collapseSlashes(path))
}

func (p *Pattern) match(value string) (map[string]string, bool) {
	matches := p.Re.FindStringSubmatch(value)
	if len(matches) == 0 {
		return nil, false
	}
	out := map[string]string{}
	names := p.Re.SubexpNames()
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		if variable := p.Groups[name]; variable != "" {
			out[variable] = matches[i]
		}
	}
	return out, true
}

func mergeCaptures(dst, src map[string]string) {
	for k, v := range src {
		if v != "" {
			dst[k] = v
		}
	}
}

func collapseSlashes(path string) string {
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}
