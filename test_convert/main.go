package main

import (
	"fmt"
	"os"

	"github.com/chainreactors/neutron/convert"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	out, err := convert.Convert(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
