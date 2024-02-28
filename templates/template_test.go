package templates

import (
	"fmt"
	"github.com/chainreactors/neutron/protocols"
	"gopkg.in/yaml.v3"
	"os"
	"testing"
)

var ExecuterOptions *protocols.ExecuterOptions

func TestTemplate_Compile(t1 *testing.T) {
	content, _ := os.ReadFile("tmp.yml")
	t := &Template{}
	err := yaml.Unmarshal(content, t)
	if err != nil {
		println(err.Error())
		return
	}
	if t != nil {
		err := t.Compile(ExecuterOptions)
		if err != nil {
			println(err.Error())
			return
		}
	}
	println("success")
}

func TestTemplate_Execute(t1 *testing.T) {
	content, _ := os.ReadFile("tmp.yml")
	t := &Template{}
	err := yaml.Unmarshal(content, t)
	if err != nil {
		println(err.Error())
		return
	}
	if t != nil {
		err := t.Compile(ExecuterOptions)
		if err != nil {
			println(err.Error())
			return
		}
	}

	println("load success")

	res, err := t.Execute("http://127.0.0.1:8089", map[string]interface{}{
		"username": "admin",
		"password": "admin",
	})
	if err == nil {
		fmt.Println("ok", res)
	} else {
		fmt.Println(res)
	}
}
