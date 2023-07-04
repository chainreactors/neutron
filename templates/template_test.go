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

	res, ok := t.Execute("http://101.132.126.116")
	if ok {
		println("ok")
	} else {
		fmt.Println(res)
	}
}

func TestTemplate_GetTags(t1 *testing.T) {

}
