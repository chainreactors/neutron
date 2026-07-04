package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/neutron/common"
	_ "github.com/chainreactors/neutron/convert"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	pathFlag := flag.String("path", "", "Path to YAML template file or directory")
	targetFlag := flag.String("target", "", "Target URL")
	jsonFlag := flag.Bool("json", false, "Output results as JSON")
	timeoutFlag := flag.Int("timeout", 5, "Request timeout in seconds")
	proxyAddr := flag.String("proxy", "", "Proxy address (e.g., http://127.0.0.1:8080)")
	debug := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	targetPath := *pathFlag
	targetURL := *targetFlag

	if targetPath == "" && len(flag.Args()) >= 1 {
		targetPath = flag.Arg(0)
	}
	if targetURL == "" && len(flag.Args()) >= 2 {
		targetURL = flag.Arg(1)
	}

	if targetPath == "" || targetURL == "" {
		fmt.Println("Usage: shot -path <template> -target <url> [-json] [-timeout N] [-proxy <addr>]")
		fmt.Println("       shot <path_or_file> <target_url>")
		os.Exit(1)
	}

	if *debug {
		logs.Log.SetLevel(logs.DebugLevel)
		common.NeutronLog = logs.Log
		spew.Config.Indent = "\t"
		spew.Config.DisablePointerAddresses = true
		spew.Config.DisableCapacities = true
		spew.Config.SortKeys = true
	}

	execOpts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: *timeoutFlag}}
	if *proxyAddr != "" {
		execOpts.Options.ProxyURL = *proxyAddr
	}

	var yamlFiles []string
	err := filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
			yamlFiles = append(yamlFiles, path)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error walking the path: %s\n", err.Error())
		os.Exit(1)
	}

	matchedCount := 0
	extractedCount := 0
	positiveCount := 0
	totalCount := len(yamlFiles)

	for _, yamlFile := range yamlFiles {
		content, err := os.ReadFile(yamlFile)
		if err != nil {
			if !*jsonFlag {
				fmt.Printf("Error reading %s: %s\n", yamlFile, err.Error())
			}
			continue
		}

		t, err := templates.Load(content)
		if err != nil {
			if !*jsonFlag {
				fmt.Printf("Error loading %s: %s\n", yamlFile, err.Error())
			}
			continue
		}

		err = t.Compile(execOpts)
		if err != nil {
			if !*jsonFlag {
				fmt.Printf("Error compiling %s: %s\n", yamlFile, err.Error())
			}
			continue
		}

		if !*jsonFlag {
			fmt.Printf("Load success for %s\n", yamlFile)
		}
		start := time.Now()
		res, err := t.Execute(targetURL, nil)
		if err == nil && res != nil && res.Matched {
			matchedCount++
			positiveCount++
			if !*jsonFlag {
				fmt.Printf("Matched: %s (%s)\n", yamlFile, time.Since(start))
			}
		} else if err == nil && res != nil && res.Extracted {
			extractedCount++
			positiveCount++
			if !*jsonFlag {
				fmt.Printf("Extracted: %s (%s)\n", yamlFile, time.Since(start))
			}
		} else if err != nil {
			if !*jsonFlag {
				fmt.Printf("Error executing %s: %s\n", yamlFile, err.Error())
			}
		} else {
			if !*jsonFlag {
				fmt.Printf("No match: %s (%s)\n", yamlFile, time.Since(start))
			}
		}
	}

	if *jsonFlag {
		out, _ := json.Marshal(map[string]interface{}{
			"matched_count":   matchedCount,
			"extracted_count": extractedCount,
			"positive_count":  positiveCount,
			"total":           totalCount,
			"target":          targetURL,
		})
		fmt.Println(string(out))
	}
}
