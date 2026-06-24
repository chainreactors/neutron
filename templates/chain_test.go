package templates

import (
	"reflect"
	"testing"
)

func TestChainExecutor_Entrypoints(t *testing.T) {
	e := NewChainExecutor(ChainConfig{})
	e.Add("root", []string{"child-a", "child-b"})
	e.Add("child-a", nil)
	e.Add("child-b", []string{"grandchild"})
	e.Add("grandchild", nil)
	e.Add("standalone", nil)

	want := []string{"root", "standalone"}
	got := e.Entrypoints()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Entrypoints() = %v, want %v", got, want)
	}
}

func TestChainExecutor_BFS(t *testing.T) {
	e := NewChainExecutor(ChainConfig{})
	e.Add("a", []string{"b"})
	e.Add("b", []string{"c"})
	e.Add("c", nil)

	var order []string
	e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return &ChainResult{}
	})

	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("BFS order = %v, want %v", order, want)
	}
}

func TestChainExecutor_DFS(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true})
	e.Add("a", []string{"b"})
	e.Add("b", []string{"c"})
	e.Add("c", nil)

	var order []string
	e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return &ChainResult{}
	})

	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("DFS order = %v, want %v", order, want)
	}
}

func TestChainExecutor_CycleProtection(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true})
	e.Add("a", []string{"b"})
	e.Add("b", []string{"a"})

	var order []string
	e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return &ChainResult{}
	})

	want := []string{"a", "b"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("cycle order = %v, want %v", order, want)
	}
}

func TestChainExecutor_PassVariables(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true, PassVariables: true})
	e.Add("parent", []string{"child"})
	e.Add("child", nil)

	var childVars map[string]interface{}
	e.Execute([]string{"parent"}, func(id string, vars map[string]interface{}) *ChainResult {
		if id == "parent" {
			return &ChainResult{Vars: map[string]interface{}{"os": "linux"}}
		}
		childVars = vars
		return &ChainResult{}
	})

	if childVars == nil || childVars["os"] != "linux" {
		t.Fatalf("child vars = %v, want map[os:linux]", childVars)
	}
}

func TestChainExecutor_NoPassVariables(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true, PassVariables: false})
	e.Add("parent", []string{"child"})
	e.Add("child", nil)

	var childVars map[string]interface{}
	e.Execute([]string{"parent"}, func(id string, vars map[string]interface{}) *ChainResult {
		if id == "parent" {
			return &ChainResult{Vars: map[string]interface{}{"os": "linux"}}
		}
		childVars = vars
		return &ChainResult{}
	})

	if childVars != nil {
		t.Fatalf("child vars = %v, want nil (PassVariables disabled)", childVars)
	}
}

func TestChainExecutor_NilResultSkipsChain(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true})
	e.Add("a", []string{"b"})
	e.Add("b", nil)

	var order []string
	e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return nil // a fails, b should not run
	})

	want := []string{"a"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("nil-result order = %v, want %v", order, want)
	}
}

func TestChainExecutor_BFS_PassVariables(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: false, PassVariables: true})
	e.Add("parent", []string{"child"})
	e.Add("child", nil)

	var childVars map[string]interface{}
	e.Execute([]string{"parent"}, func(id string, vars map[string]interface{}) *ChainResult {
		if id == "parent" {
			return &ChainResult{Vars: map[string]interface{}{"key": "val"}}
		}
		childVars = vars
		return &ChainResult{}
	})

	if childVars == nil || childVars["key"] != "val" {
		t.Fatalf("BFS child vars = %v, want map[key:val]", childVars)
	}
}

func TestChainExecutor_MultipleChains(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true})
	e.Add("root", []string{"child-a", "child-b"})
	e.Add("child-a", nil)
	e.Add("child-b", nil)

	var order []string
	e.Execute([]string{"root"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return &ChainResult{}
	})

	want := []string{"root", "child-a", "child-b"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("multiple chains order = %v, want %v", order, want)
	}
}

func TestChainExecutor_Diamond(t *testing.T) {
	// A → B, A → C, B → D, C → D — D should execute only once
	for _, df := range []bool{true, false} {
		name := "BFS"
		if df {
			name = "DFS"
		}
		t.Run(name, func(t *testing.T) {
			e := NewChainExecutor(ChainConfig{DepthFirst: df})
			e.Add("a", []string{"b", "c"})
			e.Add("b", []string{"d"})
			e.Add("c", []string{"d"})
			e.Add("d", nil)

			count := make(map[string]int)
			e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
				count[id]++
				return &ChainResult{}
			})

			for _, id := range []string{"a", "b", "c", "d"} {
				if count[id] != 1 {
					t.Errorf("%s executed %d times, want 1", id, count[id])
				}
			}
		})
	}
}

func TestChainExecutor_MissingChainTarget(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true})
	e.Add("a", []string{"missing", "b"})
	e.Add("b", nil)

	var order []string
	e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return &ChainResult{}
	})

	// "missing" is skipped (not registered), "b" still executes
	want := []string{"a", "b"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("missing target order = %v, want %v", order, want)
	}
}

func TestChainExecutor_MultiLevelVarPropagation(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: true, PassVariables: true})
	e.Add("root", []string{"mid"})
	e.Add("mid", []string{"leaf"})
	e.Add("leaf", nil)

	var leafVars map[string]interface{}
	e.Execute([]string{"root"}, func(id string, vars map[string]interface{}) *ChainResult {
		switch id {
		case "root":
			return &ChainResult{Vars: map[string]interface{}{"from_root": "yes"}}
		case "mid":
			// mid receives root's vars and adds its own
			merged := map[string]interface{}{"from_root": vars["from_root"], "from_mid": "also"}
			return &ChainResult{Vars: merged}
		case "leaf":
			leafVars = vars
			return &ChainResult{}
		}
		return nil
	})

	if leafVars == nil {
		t.Fatal("leaf vars is nil")
	}
	if leafVars["from_root"] != "yes" {
		t.Errorf("leaf missing from_root, got %v", leafVars)
	}
	if leafVars["from_mid"] != "also" {
		t.Errorf("leaf missing from_mid, got %v", leafVars)
	}
}

func TestChainExecutor_BFS_RoundOrder(t *testing.T) {
	// BFS should execute all nodes at one depth before the next
	// a → [b, c], b → d, c → d
	// Round 1: a; Round 2: b, c; Round 3: d (only once)
	e := NewChainExecutor(ChainConfig{DepthFirst: false})
	e.Add("a", []string{"b", "c"})
	e.Add("b", []string{"d"})
	e.Add("c", []string{"d"})
	e.Add("d", nil)

	var order []string
	e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return &ChainResult{}
	})

	// a first, then b and c (in registration order), then d once
	want := []string{"a", "b", "c", "d"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("BFS round order = %v, want %v", order, want)
	}
}

func TestChainExecutor_EntrypointsPreserveOrder(t *testing.T) {
	e := NewChainExecutor(ChainConfig{})
	e.Add("z-last", nil)
	e.Add("a-first", nil)
	e.Add("m-mid", []string{"z-last"})

	// z-last is a chain target of m-mid, so only a-first and m-mid are entry points
	want := []string{"a-first", "m-mid"}
	got := e.Entrypoints()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Entrypoints() = %v, want %v", got, want)
	}
}

func TestChainExecutor_BFS_CycleProtection(t *testing.T) {
	e := NewChainExecutor(ChainConfig{DepthFirst: false})
	e.Add("a", []string{"b"})
	e.Add("b", []string{"a"})

	var order []string
	e.Execute([]string{"a"}, func(id string, vars map[string]interface{}) *ChainResult {
		order = append(order, id)
		return &ChainResult{}
	})

	want := []string{"a", "b"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("BFS cycle order = %v, want %v", order, want)
	}
}
