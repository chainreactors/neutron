package harness

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chainreactors/neutron/convert"
	"gopkg.in/yaml.v3"
)

func Load(input string) ([]*POCFile, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		poc, err := loadFile(input)
		if err != nil {
			return nil, err
		}
		return []*POCFile{poc}, nil
	}

	var paths []string
	err = filepath.Walk(input, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	files := make([]*POCFile, 0, len(paths))
	for _, path := range paths {
		poc, err := loadFile(path)
		if err != nil {
			return nil, err
		}
		files = append(files, poc)
	}
	return files, nil
}

func loadFile(path string) (*POCFile, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var poc convert.XrayPOC
	if err := yaml.Unmarshal(data, &poc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &POCFile{Path: path, Data: data, POC: &poc}, nil
}
