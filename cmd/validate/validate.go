package main

import (
	"fmt"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"path/filepath"
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
				fmt.Printf("Error unmarshalling %s: %s\n", path, err.Error())
				return nil
			}
			err = t.Compile(ExecuterOptions)
			if err != nil {
				fmt.Printf("Error compiling %s: %s\n", path, err.Error())
				return nil
			}
			fmt.Printf("Successfully validated and compiled %s\n", path)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error:", err)
	}
}
