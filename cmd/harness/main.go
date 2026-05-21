package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/chainreactors/neutron/harness"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  harness serve  -i <xray-poc-file-or-dir> [-listen 127.0.0.1:7788] [-max-delay 10s]")
	fmt.Fprintln(os.Stderr, "  harness verify -i <xray-poc-file-or-dir> [-json] [-workers 4] [-fail-only] [-debug] [-max-delay 10s]")
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	input := fs.String("i", "", "input xray POC file or directory")
	listen := fs.String("listen", "127.0.0.1:7788", "listen address")
	maxDelay := fs.Duration("max-delay", harness.DefaultMaxDelay, "maximum response delay to model")
	_ = fs.Parse(args)
	if *input == "" {
		fs.Usage()
		os.Exit(2)
	}
	files, err := harness.Load(*input)
	if err != nil {
		fatal(err)
	}
	var scenarios []*harness.Scenario
	for _, file := range files {
		built, err := harness.BuildScenarios(file.POC, harness.Options{MaxDelay: *maxDelay})
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", file.Path, err)
			continue
		}
		for _, scenario := range built {
			if scenario.Supported() {
				scenarios = append(scenarios, scenario)
			}
		}
	}
	if len(scenarios) == 0 {
		fatal(fmt.Errorf("no supported scenarios"))
	}
	fmt.Fprintf(os.Stderr, "serving %d scenario(s) on http://%s\n", len(scenarios), *listen)
	if err := http.ListenAndServe(*listen, harness.NewServer(scenarios).Handler()); err != nil {
		fatal(err)
	}
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	input := fs.String("i", "", "input xray POC file or directory")
	jsonOut := fs.Bool("json", false, "emit JSON report")
	failOnly := fs.Bool("fail-only", false, "only print non-ok file rows in text mode")
	workers := fs.Int("workers", 1, "parallel workers")
	maxDelay := fs.Duration("max-delay", harness.DefaultMaxDelay, "maximum response delay to model")
	debug := fs.Bool("debug", false, "include per-request execution trace in report")
	_ = fs.Parse(args)
	if *input == "" {
		fs.Usage()
		os.Exit(2)
	}
	report, err := harness.Verify(*input, harness.VerifyOptions{Workers: *workers, Debug: *debug, Options: harness.Options{MaxDelay: *maxDelay}})
	if err != nil {
		fatal(err)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal(err)
		}
		return
	}
	fmt.Printf("total=%d ok=%d divergent=%d unsupported=%d convert_error=%d compile_error=%d execute_error=%d\n",
		report.Total, report.OK, report.Divergent, report.Unsupported, report.ConvertError, report.CompileError, report.ExecuteError)
	for _, file := range report.Files {
		if *failOnly && file.Status == harness.StatusOK {
			continue
		}
		line := fmt.Sprintf("%s %s", file.Status, file.Path)
		if file.Reason != "" {
			line += " - " + file.Reason
		}
		if len(file.Unsupported) > 0 && file.Status != harness.StatusOK {
			line += " [" + strings.Join(file.Unsupported, "; ") + "]"
		}
		fmt.Println(line)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
