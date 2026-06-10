package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

var ExecuterOptions *protocols.ExecuterOptions

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: validate <path_or_file>")
		return
	}

	target := os.Args[1]
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			t := &templates.Template{}
			err = yaml.Unmarshal(content, &t)
			if err != nil {
				fmt.Printf("FAIL %s - YAML unmarshalling failed: %s\n", path, err.Error())
				return nil
			}

			err = t.Compile(ExecuterOptions)
			if err != nil {
				fmt.Printf("FAIL %s - Template compilation failed: %s\n", path, err.Error())
				return nil
			}

			fmt.Printf("OK   %s\n", path)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error:", err)
	}
}
