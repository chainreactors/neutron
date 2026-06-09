package http

import (
	"fmt"

	"github.com/chainreactors/neutron/protocols"
	"gopkg.in/yaml.v3"
)

func init() {
	protocols.RegisterProtocol("http", parseRequests, "requests")
}

func parseRequests(node *yaml.Node) ([]protocols.Request, error) {
	var requests []*Request
	if err := node.Decode(&requests); err != nil {
		return nil, err
	}
	result := make([]protocols.Request, 0, len(requests))
	for i, r := range requests {
		if r == nil {
			return nil, fmt.Errorf("http request at index %d is nil", i)
		}
		result = append(result, r)
	}
	return result, nil
}
