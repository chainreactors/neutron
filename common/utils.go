package common

import (
	"github.com/chainreactors/logs"
	"os"
	"reflect"
)

var NeutronLog = logs.Log

func IsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

// MergeMapsMany merges many maps into a new map
func MergeMapsMany(maps ...interface{}) map[string][]string {
	m := make(map[string][]string)
	for _, gotMap := range maps {
		val := reflect.ValueOf(gotMap)
		if val.Kind() != reflect.Map {
			continue
		}
		appendToSlice := func(key, value string) {
			if values, ok := m[key]; !ok {
				m[key] = []string{value}
			} else {
				m[key] = append(values, value)
			}
		}
		for _, e := range val.MapKeys() {
			v := val.MapIndex(e)
			switch v.Kind() {
			case reflect.Slice, reflect.Array:
				for i := 0; i < v.Len(); i++ {
					appendToSlice(e.String(), v.Index(i).String())
				}
			case reflect.String:
				appendToSlice(e.String(), v.String())
			case reflect.Interface:
				switch data := v.Interface().(type) {
				case string:
					appendToSlice(e.String(), data)
				case []string:
					for _, value := range data {
						appendToSlice(e.String(), value)
					}
				}
			}
		}
	}
	return m
}
