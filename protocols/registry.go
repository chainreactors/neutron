package protocols

import "gopkg.in/yaml.v3"

// ProtocolParser deserializes a YAML node into protocol-specific Request slices.
type ProtocolParser func(node *yaml.Node) ([]Request, error)

type protocolEntry struct {
	name   string
	parser ProtocolParser
}

var protocolRegistry = map[string]*protocolEntry{}

// RegisterProtocol registers a protocol parser under the given name and optional
// aliases. When a template YAML contains a key matching name or any alias, the
// corresponding parser is invoked to produce Request instances.
func RegisterProtocol(name string, parser ProtocolParser, aliases ...string) {
	entry := &protocolEntry{name: name, parser: parser}
	protocolRegistry[name] = entry
	for _, alias := range aliases {
		protocolRegistry[alias] = entry
	}
}

// IsRegisteredProtocol reports whether key is a registered protocol name or alias.
func IsRegisteredProtocol(key string) bool {
	_, ok := protocolRegistry[key]
	return ok
}

// ParseProtocolRequests parses a YAML node using the registered parser for key.
// Returns (nil, nil) if key is not a registered protocol.
func ParseProtocolRequests(key string, node *yaml.Node) ([]Request, error) {
	entry, ok := protocolRegistry[key]
	if !ok {
		return nil, nil
	}
	return entry.parser(node)
}
