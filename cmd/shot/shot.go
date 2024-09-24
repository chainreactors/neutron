package main

import (
	"fmt"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
	"net/url"
	"os"
	"time"
)

var ExecuterOptions *protocols.ExecuterOptions

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: shot <path_or_file> <target_url>")
		return
	}

	yamlFile := os.Args[1]
	targetURL := os.Args[2]

	content, err := os.ReadFile(yamlFile)
	if err != nil {
		fmt.Printf("Error reading %s: %s\n", yamlFile, err.Error())
		return
	}

	t := &templates.Template{}
	err = yaml.Unmarshal(content, t)
	if err != nil {
		fmt.Printf("Error unmarshalling %s: %s\n", yamlFile, err.Error())
		return
	}

	err = t.Compile(ExecuterOptions)
	if err != nil {
		fmt.Printf("Error compiling %s: %s\n", yamlFile, err.Error())
		return
	}

	fmt.Println("Load success")
	_, err = url.Parse(targetURL)
	if err != nil {
		fmt.Println(err.Error())
	}
	start := time.Now()
	res, err := t.Execute(targetURL, nil)
	if err == nil {
		fmt.Println("OK:", res)
	} else {
		fmt.Println("Error:", res)
	}
	fmt.Println("Execution time:", time.Since(start))
}
