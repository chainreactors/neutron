package dsl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
)

type dslFunction struct {
	IsCacheable bool
	Name        string
	// if numberOfArgs is defined the signature is automatically generated
	NumberOfArgs       int
	Signatures         []string
	ExpressionFunction govaluate.ExpressionFunction
	// IsFieldTransparent marks functions that do not change the identity of
	// the response part they wrap (e.g. to_lower, to_upper). The codegen
	// layer uses this to "see through" wrapping calls and identify the
	// underlying field variable.
	IsFieldTransparent bool
}

func (d dslFunction) GetSignatures() []string {
	// fixed number of args implies a static signature
	if d.NumberOfArgs > 0 {
		args := make([]string, 0, d.NumberOfArgs)
		for i := 1; i <= d.NumberOfArgs; i++ {
			args = append(args, "arg"+strconv.Itoa(i))
		}
		argsPart := fmt.Sprintf("(%s interface{}) interface{}", strings.Join(args, ", "))
		signature := d.Name + argsPart
		return []string{signature}
	}

	// multi signatures
	var signatures []string
	for _, signature := range d.Signatures {
		signatures = append(signatures, d.Name+signature)
	}

	return signatures
}

func (d dslFunction) Exec(args ...interface{}) (interface{}, error) {
	// fixed number of args implies the possibility to perform matching between the expected number of args and the ones provided
	if d.NumberOfArgs > 0 {
		if len(args) != d.NumberOfArgs {
			signatures := d.GetSignatures()
			if len(signatures) > 0 {
				return nil, fmt.Errorf("%v. correct method signature %q", ErrInvalidDslFunction, signatures[0])
			}
			return nil, ErrInvalidDslFunction
		}
	}

	if !d.IsCacheable {
		return d.ExpressionFunction(args...)
	}

	//functionHash := d.hash()
	//if result, err := resultCache.Get(functionHash); err == nil {
	//	return result, nil
	//}

	result, err := d.ExpressionFunction(args...)
	//if err == nil {
	//	_ = resultCache.Set(functionHash, result)
	//}

	return result, err
}

func (d dslFunction) WithFieldTransparent() dslFunction {
	d.IsFieldTransparent = true
	return d
}

func (d dslFunction) hash(args ...interface{}) string {
	return fmt.Sprintf(d.Name, args...)
}
