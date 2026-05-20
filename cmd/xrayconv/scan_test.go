package main

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	gohttp "net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	nhttp "github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

func TestScanRange(t *testing.T) {
	tmpls := loadTemplates(t)
	t.Logf("Loaded %d templates", len(tmpls))

	var targets []string
	for i := 1; i < 255; i++ {
		ip := fmt.Sprintf("101.132.149.%d", i)
		targets = append(targets, fmt.Sprintf("http://%s", ip))
		targets = append(targets, fmt.Sprintf("https://%s", ip))
	}

	t.Log("Probing alive targets...")
	alive := probeAlive(targets, 3*time.Second, 50)
	t.Logf("Alive: %d / %d", len(alive), len(targets))
	if len(alive) == 0 {
		t.Skip("No alive targets")
	}

	client := &gohttp.Client{
		Timeout: 10 * time.Second,
		Transport: &gohttp.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *gohttp.Request, via []*gohttp.Request) error {
			if len(via) >= 3 {
				return gohttp.ErrUseLastResponse
			}
			return nil
		},
	}

	type result struct {
		URL    string
		Frames []string
	}
	var mu sync.Mutex
	var results []result
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for _, target := range alive {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			data, err := fetchAndBuildData(client, url)
			if err != nil {
				return
			}

			var matched []string
			for _, tmpl := range tmpls {
				for _, req := range tmpl.GetRequests() {
					if req.CompiledOperators == nil || len(req.CompiledOperators.Matchers) == 0 {
						continue
					}
					if matchReq(req, data) {
						name := tmpl.Info.Name
						if name == "" {
							name = tmpl.Id
						}
						matched = append(matched, name)
						break
					}
				}
			}

			if len(matched) > 0 {
				mu.Lock()
				results = append(results, result{URL: url, Frames: matched})
				mu.Unlock()
			}
		}(target)
	}
	wg.Wait()

	t.Logf("\n=== Fingerprint Results (%d hits) ===", len(results))
	for _, r := range results {
		t.Logf("  %-45s %s", r.URL, strings.Join(r.Frames, ", "))
	}
}

func loadTemplates(t *testing.T) []*templates.Template {
	f, err := os.Open("/mnt/chainreactors/fingers/resources/fingerprinthub_xray_web.json.gz")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	defer gz.Close()

	var raw []map[string]interface{}
	json.NewDecoder(gz).Decode(&raw)

	var result []*templates.Template
	for _, r := range raw {
		yb, _ := yaml.Marshal(r)
		tmpl := &templates.Template{}
		if yaml.Unmarshal(yb, tmpl) != nil {
			continue
		}
		if tmpl.Compile(nil) != nil {
			for _, req := range tmpl.GetRequests() {
				(&req.Operators).Compile()
				req.CompiledOperators = &req.Operators
			}
		}
		if tmpl.GetRequests() != nil {
			result = append(result, tmpl)
		}
	}
	return result
}

func probeAlive(targets []string, timeout time.Duration, conc int) []string {
	var alive []string
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
			port := "80"
			if strings.HasPrefix(url, "https://") {
				port = "443"
			}
			conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			alive = append(alive, url)
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	return alive
}

func fetchAndBuildData(client *gohttp.Client, url string) (map[string]interface{}, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	data := map[string]interface{}{
		"status_code":    resp.StatusCode,
		"body":           string(body),
		"content_length": len(body),
	}
	var hdr strings.Builder
	for k, vals := range resp.Header {
		joined := strings.Join(vals, " ")
		norm := strings.ToLower(strings.Replace(strings.TrimSpace(k), "-", "_", -1))
		data[norm] = joined
		fmt.Fprintf(&hdr, "%s: %s\r\n", norm, joined)
	}
	data["all_headers"] = hdr.String()
	data["header"] = hdr.String()
	return data, nil
}

func matchReq(req *nhttp.Request, data map[string]interface{}) bool {
	cond := strings.ToLower(strings.TrimSpace(req.CompiledOperators.MatchersCondition))
	if cond == "" {
		cond = "or"
	}
	any, all := false, true
	for _, m := range req.CompiledOperators.Matchers {
		ok, _ := req.Match(data, m)
		if ok {
			any = true
		} else {
			all = false
		}
	}
	if cond == "and" {
		return all && len(req.CompiledOperators.Matchers) > 0
	}
	return any
}
