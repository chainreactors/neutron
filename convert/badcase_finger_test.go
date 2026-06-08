package convert

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

// TestBadCaseFinger_R5_Compile 守住 SDK v0.2.4 实跑里出现的 22 个 bad-case
// 指纹 YAML 至少能被 Convert+Compile 处理掉,不留 panic / 不返 error。
// 这条 case 是离线的(无网络),CI 默认跑这条。
//
// 实测命中率验证在 TestBadCaseFinger_R5_LiveTargets,默认 -short 跳过。
func TestBadCaseFinger_R5_Compile(t *testing.T) {
	dir := "testdata/badcase_finger_r5_20260608"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read testdata dir: %v", err)
	}
	yamlCount := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		yamlCount++
		t.Run(e.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			converted, err := Convert(raw)
			if err != nil {
				t.Fatalf("convert: %v", err)
			}
			var tmpl templates.Template
			if err := yaml.Unmarshal(converted, &tmpl); err != nil {
				t.Fatalf("unmarshal converted template: %v\n%s", err, converted)
			}
			if err := tmpl.Compile(nil); err != nil {
				t.Fatalf("compile converted template: %v\n%s", err, converted)
			}
		})
	}
	if yamlCount == 0 {
		t.Fatalf("no yaml files found under %s", dir)
	}
}

// TestBadCaseFinger_R5_LiveTargets 拉 testdata/.../urls.tsv 里每个 URL 实跑一次,
// 把当前命中数 vs r5 基线打到测试输出。**不会** 因命中数下降而 fail——回归对比
// 在脚本侧做,这里只是把数据落到 CI 日志里给 reviewer 看。
//
// 默认 -short 模式跳过(CI 不联网);手动复现用 `go test -run BadCaseFinger -timeout 30m`。
func TestBadCaseFinger_R5_LiveTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("live network test; pass -timeout 30m and unset -short to run")
	}
	dir := "testdata/badcase_finger_r5_20260608"
	urlsPath := filepath.Join(dir, "urls.tsv")
	rows, err := loadBadCaseURLs(urlsPath)
	if err != nil {
		t.Fatalf("load urls.tsv: %v", err)
	}
	// 按 yaml_file 分组,每个 yaml 只 Convert+Compile 一次,然后扫一遍它的 URL。
	byFile := map[string][]badCaseRow{}
	for _, r := range rows {
		byFile[r.YAMLFile] = append(byFile[r.YAMLFile], r)
	}
	for fname, group := range byFile {
		t.Run(fname, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, fname))
			if err != nil {
				t.Fatalf("read %s: %v", fname, err)
			}
			converted, err := Convert(raw)
			if err != nil {
				t.Fatalf("convert %s: %v", fname, err)
			}
			var tmpl templates.Template
			if err := yaml.Unmarshal(converted, &tmpl); err != nil {
				t.Fatalf("unmarshal %s: %v", fname, err)
			}
			if err := tmpl.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 8}}); err != nil {
				t.Fatalf("compile %s: %v", fname, err)
			}
			var nowHit, r5Hit int
			for _, row := range group {
				if row.R5Match {
					r5Hit++
				}
				deadline := time.Now().Add(30 * time.Second)
				resultCh := make(chan bool, 1)
				go func(url string) {
					res, _ := tmpl.Execute(url, nil)
					resultCh <- res != nil && res.Matched
				}(row.URL)
				select {
				case ok := <-resultCh:
					if ok {
						nowHit++
					}
				case <-time.After(time.Until(deadline)):
					// 当前 URL 超时按未命中算,与 r5 时刻处理一致。
				}
			}
			t.Logf("%s  now=%d/%d  r5=%d/%d", fname, nowHit, len(group), r5Hit, len(group))
		})
	}
}

type badCaseRow struct {
	YAMLFile string
	Product  string
	URL      string
	R5Match  bool
}

func loadBadCaseURLs(path string) ([]badCaseRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []badCaseRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		out = append(out, badCaseRow{
			YAMLFile: fields[0],
			Product:  fields[1],
			URL:      fields[2],
			R5Match:  strings.EqualFold(fields[3], "true"),
		})
	}
	return out, sc.Err()
}
