package protocols

import (
	"testing"
)

func TestPitchforkValidation(t *testing.T) {
	_, err := NewGenerator(map[string]interface{}{
		"a": []string{"1", "2", "3"},
		"b": []string{"x", "y"},
	}, PitchFork)
	if err == nil {
		t.Fatal("expected error for unequal pitchfork payload lengths")
	}
}

func TestPitchforkEqualLength(t *testing.T) {
	gen, err := NewGenerator(map[string]interface{}{
		"a": []string{"1", "2"},
		"b": []string{"x", "y"},
	}, PitchFork)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	iter := gen.NewIterator()
	if iter.Total() != 2 {
		t.Fatalf("expected total 2, got %d", iter.Total())
	}

	v1, ok := iter.Value()
	if !ok {
		t.Fatal("expected first value")
	}
	if v1["a"] != "1" || v1["b"] != "x" {
		t.Fatalf("expected a=1,b=x, got a=%v,b=%v", v1["a"], v1["b"])
	}

	v2, ok := iter.Value()
	if !ok {
		t.Fatal("expected second value")
	}
	if v2["a"] != "2" || v2["b"] != "y" {
		t.Fatalf("expected a=2,b=y, got a=%v,b=%v", v2["a"], v2["b"])
	}

	_, ok = iter.Value()
	if ok {
		t.Fatal("expected no more values")
	}
}

func TestPitchforkDeterministicOrder(t *testing.T) {
	payloads := map[string]interface{}{
		"z": []string{"z1", "z2"},
		"a": []string{"a1", "a2"},
		"m": []string{"m1", "m2"},
	}

	for i := 0; i < 20; i++ {
		gen, err := NewGenerator(payloads, PitchFork)
		if err != nil {
			t.Fatalf("run %d: unexpected error: %v", i, err)
		}
		iter := gen.NewIterator()
		v, ok := iter.Value()
		if !ok {
			t.Fatalf("run %d: expected value", i)
		}
		if v["a"] != "a1" || v["m"] != "m1" || v["z"] != "z1" {
			t.Fatalf("run %d: expected a=a1,m=m1,z=z1, got a=%v,m=%v,z=%v", i, v["a"], v["m"], v["z"])
		}
	}
}

func TestPitchforkEmptyPayloads(t *testing.T) {
	gen, err := NewGenerator(map[string]interface{}{}, PitchFork)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	iter := gen.NewIterator()
	if iter.Total() != 0 {
		t.Fatalf("expected total 0, got %d", iter.Total())
	}
}

func TestClusterBombValues(t *testing.T) {
	gen, err := NewGenerator(map[string]interface{}{
		"a": []string{"1", "2"},
		"b": []string{"x", "y"},
	}, ClusterBomb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	iter := gen.NewIterator()
	if iter.Total() != 4 {
		t.Fatalf("expected total 4, got %d", iter.Total())
	}
}
