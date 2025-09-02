package main

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"github.com/invopop/jsonschema"
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

			// Step 1: Generate JSONSchema from Template struct
			reflector := jsonschema.Reflector{}
			schema := reflector.Reflect(&templates.Template{})
			_, err = json.Marshal(schema)
			if err != nil {
				fmt.Printf("Error generating schema for %s: %s\n", path, err.Error())
				return nil
			}
			// Step 4: Unmarshal into template struct for structural validation
			t := &templates.Template{}
			err = yaml.Unmarshal(content, &t)
			if err != nil {
				fmt.Printf("❌ %s - YAML unmarshalling failed: %s\n", path, err.Error())
				return nil
			}

			// Step 5: Compile template for content validation
			err = t.Compile(ExecuterOptions)
			if err != nil {
				fmt.Printf("❌ %s - Template compilation failed: %s\n", path, err.Error())
				return nil
			}

			fmt.Printf("✅ %s - All validations passed\n", path)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error:", err)
	}
}
