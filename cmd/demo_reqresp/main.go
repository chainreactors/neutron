package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

func main() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Set-Cookie", "session=eyJhbGciOiJIUzI1NiJ9")
			w.WriteHeader(200)
			fmt.Fprint(w, `{"code":0,"msg":"ok","data":{"csrf_token":"x9f2k1m3"}}`)
		case "/api/userinfo":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			fmt.Fprint(w, `{"code":0,"user":{"id":1,"role":"admin","name":"root"}}`)
		case "/admin/config":
			w.Header().Set("X-Powered-By", "Express/4.17.1")
			w.WriteHeader(200)
			fmt.Fprint(w, `{"debug":true,"secret_key":"sk-prod-abc123","db_host":"10.0.0.5"}`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer server.Close()

	yamlContent := `
id: multi-request-info-leak
info:
  name: Multi Request Info Leak Detection
  author: test
  severity: critical
  description: Detect information leak via multi-step API chain

http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: "username=admin&password=admin"
    extractors:
      - type: regex
        name: csrf
        regex:
          - '"csrf_token":"([a-z0-9]+)"'
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}/api/userinfo"
    headers:
      X-CSRF-Token: "{{csrf}}"
    matchers:
      - type: word
        words:
          - '"role":"admin"'
    extractors:
      - type: regex
        name: username
        regex:
          - '"name":"(\w+)"'

  - method: GET
    path:
      - "{{BaseURL}}/admin/config"
    matchers:
      - type: word
        words:
          - "secret_key"
          - "db_host"
        condition: and
`
	var tmpl templates.Template
	if err := yaml.Unmarshal([]byte(yamlContent), &tmpl); err != nil {
		fmt.Printf("YAML parse error: %v\n", err)
		return
	}
	if err := tmpl.Compile(nil); err != nil {
		fmt.Printf("Compile error: %v\n", err)
		return
	}

	result, events, err := tmpl.ExecuteWithEvents(server.URL, nil)
	if err != nil {
		fmt.Printf("Execute error: %v\n", err)
		return
	}

	fmt.Printf("Template: %s\n", tmpl.Id)
	fmt.Printf("Matched:  %v\n", result != nil && result.Matched)
	fmt.Printf("Events:   %d\n", len(events))

	if result != nil && len(result.Extracts) > 0 {
		fmt.Printf("Extracts: %v\n", result.Extracts)
	}

	for i, ev := range events {
		fmt.Printf("\n%s Event %d/%d %s\n", strings.Repeat("=", 20), i+1, len(events), strings.Repeat("=", 20))
		if ev.Request != "" {
			fmt.Printf("\n>>> REQUEST >>>\n%s\n", ev.Request)
		}
		if ev.Response != "" {
			fmt.Printf("\n<<< RESPONSE <<<\n%s\n", ev.Response)
		}
	}
}
