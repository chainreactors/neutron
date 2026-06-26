// validate checks that neutron/nuclei templates compile correctly, and
// optionally compares xray POC semantics against converted templates.
//
// Usage:
//
//	validate <path_or_file>                                     # compile check
//	validate compare --xray <xray.yml> --nuclei <nuclei.yaml>   # semantic comparison
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	_ "github.com/chainreactors/neutron/convert"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: validate <path_or_file>")
		fmt.Println("       validate compare --xray <xray.yml> --nuclei <nuclei.yaml> [--json] [-v]")
		os.Exit(1)
	}

	if os.Args[1] == "compare" {
		runCompare(os.Args[2:])
		return
	}

	target := os.Args[1]
	opts := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		t, err := templates.Load(content)
		if err != nil {
			fmt.Printf("FAIL %s - load failed: %s\n", path, err.Error())
			return nil
		}

		err = t.Compile(opts)
		if err != nil {
			fmt.Printf("FAIL %s - compile failed: %s\n", path, err.Error())
			return nil
		}

		fmt.Printf("OK   %s\n", path)
		return nil
	})

	if err != nil {
		fmt.Println("Error:", err)
	}
}
