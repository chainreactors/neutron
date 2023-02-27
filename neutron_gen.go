package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
)

var (
	templatePath string
	resultPath   string
)

func main() {
	var needs []string
	flag.StringVar(&templatePath, "t", ".", "templates repo path")
	flag.StringVar(&resultPath, "o", "templates.go", "result filename")
	need := flag.String("need", "http,network,file", "http,network,file")
	flag.Parse()

	if *need == "gogo" {
		needs = []string{"http", "network"}
	} else if *need == "found" {
		needs = []string{"http", "network", "file"}
	} else {
		needs = strings.Split(*need, ",")
	}

	var s strings.Builder
	var im strings.Builder
	for _, n := range needs {
		switch n {
		case "file":
			im.WriteString("\t\"github.com/chainreactors/neutron/protocols/file\"\n")
			s.WriteString("\tRequestFile     []file.Request    `json:\"request_file\" yaml:\"file\"`\n")
		case "http":
			im.WriteString("\t\"github.com/chainreactors/neutron/protocols/http\"\n")
			s.WriteString("\tRequestsHTTP    []http.Request    `json:\"requests\" yaml:\"requests\"`\n")
		case "network":
			im.WriteString("\t\"github.com/chainreactors/neutron/protocols/network\"\n")
			s.WriteString("\tRequestsNetwork []network.Request `json:\"network\" yaml:\"network\"`\n")
		default:
			println("invalid type: ", n)
		}
	}

	content, err := ioutil.ReadFile(templatePath + "/templates/template.txt")
	if err != nil {
		println(err.Error())
		return
	}
	res := fmt.Sprintf(string(content), im.String(), s.String())
	err = ioutil.WriteFile(templatePath+"/templates/template.go", []byte(res), 0644)
	if err != nil {
		println(err.Error())
	}
}
