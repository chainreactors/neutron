// runpoc is a minimal example: load a POC (xray or neutron format,
// auto-detected) and execute it against a target.
//
//	runpoc <poc.yaml> <target-url>
//
// Example:
//
//	runpoc ./08cms.yaml http://example.com
package main

import (
	"fmt"
	"os"

	_ "github.com/chainreactors/neutron/convert" // registers the xray converter
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: runpoc <poc.yaml> <target-url>")
		os.Exit(2)
	}
	pocPath, target := os.Args[1], os.Args[2]

	data, err := os.ReadFile(pocPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read poc: %v\n", err)
		os.Exit(1)
	}

	// 1. Load — format is auto-detected; xray POCs are converted on the fly.
	tmpl, err := templates.Load(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}

	// 2. Compile — builds the executor from the template's requests.
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 10}}
	if err := tmpl.Compile(opts); err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		os.Exit(1)
	}

	// 3. Execute — sends the request(s) and evaluates matchers.
	result, err := tmpl.Execute(target, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execute: %v\n", err)
		os.Exit(1)
	}

	if result != nil && result.Matched {
		fmt.Printf("[+] %s matched %s\n", tmpl.Id, target)
		if len(result.OutputExtracts) > 0 {
			fmt.Printf("    extracts: %v\n", result.OutputExtracts)
		}
	} else {
		fmt.Printf("[-] %s did not match %s\n", tmpl.Id, target)
	}
}
