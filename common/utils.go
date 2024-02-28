package common

import (
	"fmt"
	"github.com/chainreactors/logs"
	"os"
	"reflect"
	"strconv"
	"strings"
)

var NeutronLog = logs.Log

func IsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

// MergeMaps merges two maps into a New map
func MergeMaps(m1, m2 map[string]interface{}) map[string]interface{} {
	m := make(map[string]interface{}, len(m1)+len(m2))
	for k, v := range m1 {
		m[k] = v
	}
	for k, v := range m2 {
		m[k] = v
	}
	return m
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

func MapToString(m map[string]interface{}) string {
	if m == nil || len(m) == 0 {
		return ""
	}
	var s string
	for k, v := range m {
		s += fmt.Sprintf(" %s:%s ", k, v.(string))
	}
	return s
}

// IndexAt look for a substring starting at position x
func IndexAt(s, sep string, n int) int {
	idx := strings.Index(s[n:], sep)
	if idx > -1 {
		idx += n
	}
	return idx
}

func ToString(data interface{}) string {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case fmt.Stringer:
		return s.String()
	case error:
		return s.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
}

func StringsContains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}
