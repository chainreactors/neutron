// xrayconv converts xray POC YAML files to neutron/nuclei template files.
//
// Usage:
//
//	xrayconv -i <input-dir> -o <output-dir>              # YAML per file
//	xrayconv -i <input-dir> -o output.json -format json   # single JSON array
//	xrayconv -i <input-dir> -o output.json.gz -format json # gzipped JSON array
//	xrayconv -i <file.yaml>                                # single file to stdout
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/neutron/convert"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		inputPath  string
		outputPath string
		format     string
		workers    int
	)
	flag.StringVar(&inputPath, "i", "", "input xray POC file or directory")
	flag.StringVar(&outputPath, "o", "", "output directory or file (omit for stdout on single file)")
	flag.StringVar(&format, "format", "yaml", "output format: yaml (per-file) or json (single array)")
	flag.IntVar(&workers, "w", 8, "number of parallel workers for batch conversion")
	flag.Parse()

	if inputPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: xrayconv -i <input> [-o <output>] [-format yaml|json]")
		os.Exit(2)
	}

	info, err := os.Stat(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if !info.IsDir() {
		singleFile(inputPath, outputPath)
		return
	}

	if format == "json" {
		batchJSON(inputPath, outputPath, workers)
	} else {
		batchYAML(inputPath, outputPath, workers)
	}
}

func singleFile(inputPath, outputPath string) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}
	out, err := convert.Convert(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "convert: %v\n", err)
		os.Exit(1)
	}
	if outputPath != "" {
		os.MkdirAll(filepath.Dir(outputPath), 0755)
		if err := os.WriteFile(outputPath, out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", outputPath)
	} else {
		fmt.Print(string(out))
	}
}

func batchJSON(inputDir, outputPath string, workers int) {
	if outputPath == "" {
		fmt.Fprintln(os.Stderr, "json format requires -o <output.json>")
		os.Exit(2)
	}

	files, err := listYAML(inputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list: %v\n", err)
		os.Exit(1)
	}

	type result struct {
		data map[string]interface{}
		name string
	}

	var (
		total   int64
		success int64
		failed  int64
		mu      sync.Mutex
		results []result
		errors  []string
	)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&total, 1)
			base := filepath.Base(path)

			data, err := os.ReadFile(path)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				errors = append(errors, base+": "+err.Error())
				mu.Unlock()
				return
			}

			out, err := convert.Convert(data)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				errors = append(errors, base+": "+err.Error())
				mu.Unlock()
				return
			}

			// Parse YAML back to map for JSON output
			var tmplMap map[string]interface{}
			if err := yaml.Unmarshal(out, &tmplMap); err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				errors = append(errors, base+": yaml parse: "+err.Error())
				mu.Unlock()
				return
			}

			atomic.AddInt64(&success, 1)
			mu.Lock()
			results = append(results, result{data: tmplMap, name: base})
			mu.Unlock()
		}(f)
	}

	wg.Wait()

	// Sort by name for deterministic output
	sort.Slice(results, func(i, j int) bool { return results[i].name < results[j].name })

	// Extract just the maps
	var jsonArray []map[string]interface{}
	for _, r := range results {
		jsonArray = append(jsonArray, r.data)
	}

	// Write JSON (optionally gzipped)
	isGzip := strings.HasSuffix(outputPath, ".gz")
	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if isGzip {
		gz := gzip.NewWriter(f)
		enc := json.NewEncoder(gz)
		enc.SetIndent("", "  ")
		if err := enc.Encode(jsonArray); err != nil {
			fmt.Fprintf(os.Stderr, "encode: %v\n", err)
			os.Exit(1)
		}
		gz.Close()
	} else {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(jsonArray); err != nil {
			fmt.Fprintf(os.Stderr, "encode: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "Converted %d/%d → %s (%d failed)\n", success, total, outputPath, failed)
	printErrors(errors)
}

func batchYAML(inputDir, outputDir string, workers int) {
	if outputDir == "" {
		fmt.Fprintln(os.Stderr, "yaml batch mode requires -o <output-dir>")
		os.Exit(2)
	}
	os.MkdirAll(outputDir, 0755)

	files, err := listYAML(inputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list: %v\n", err)
		os.Exit(1)
	}

	var (
		total   int64
		success int64
		failed  int64
		mu      sync.Mutex
		errors  []string
	)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&total, 1)
			base := filepath.Base(path)
			data, err := os.ReadFile(path)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				errors = append(errors, base+": "+err.Error())
				mu.Unlock()
				return
			}

			out, err := convert.Convert(data)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				errors = append(errors, base+": "+err.Error())
				mu.Unlock()
				return
			}

			outPath := filepath.Join(outputDir, base)
			if err := os.WriteFile(outPath, out, 0644); err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				errors = append(errors, base+": write: "+err.Error())
				mu.Unlock()
				return
			}
			atomic.AddInt64(&success, 1)
		}(f)
	}

	wg.Wait()
	fmt.Fprintf(os.Stderr, "Converted %d/%d files (%d failed)\n", success, total, failed)
	printErrors(errors)
}

func printErrors(errors []string) {
	if len(errors) == 0 {
		return
	}
	sort.Strings(errors)
	limit := 20
	if len(errors) < limit {
		limit = len(errors)
	}
	fmt.Fprintf(os.Stderr, "Errors:\n")
	for _, e := range errors[:limit] {
		fmt.Fprintf(os.Stderr, "  %s\n", e)
	}
	if len(errors) > 20 {
		fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(errors)-20)
	}
}

func listYAML(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	return files, nil
}
