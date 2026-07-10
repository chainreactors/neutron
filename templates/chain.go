package templates

// ChainConfig controls chain execution behavior.
type ChainConfig struct {
	// DepthFirst uses recursive DFS (execute chains immediately after parent).
	// When false, uses BFS (execute all templates in a round, then their chains).
	DepthFirst bool
	// PassVariables enables forwarding extracted values from parent to child templates.
	PassVariables bool
}

// ChainResult is returned by the execute callback to signal success.
// A nil return means the template did not match or failed — its chains are skipped.
type ChainResult struct {
	// Vars holds values to forward to chained templates when PassVariables is enabled.
	Vars map[string]interface{}
}

// ExecuteFunc is called for each template during chain walking.
// id is the template ID; vars carries forwarded values from the parent
// (nil when PassVariables is false or for entry-point templates).
// Return a non-nil ChainResult to continue into this template's chains.
type ExecuteFunc func(id string, vars map[string]interface{}) *ChainResult

// ChainExecutor walks a directed graph of templates connected by chain references.
// Templates are registered by ID; the executor determines entry points (templates
// not referenced as a chain target) and walks chains with deduplication.
type ChainExecutor struct {
	chains       map[string][]string
	chainTargets map[string]bool
	order        []string
	config       ChainConfig
}

// NewChainExecutor creates a ChainExecutor with the given config.
func NewChainExecutor(config ChainConfig) *ChainExecutor {
	return &ChainExecutor{
		chains:       make(map[string][]string),
		chainTargets: make(map[string]bool),
		config:       config,
	}
}

// Add registers a template by its ID and the IDs it chains to.
// Safe to call on a nil receiver (no-op).
func (e *ChainExecutor) Add(id string, chainIDs []string) {
	if e == nil {
		return
	}
	e.chains[id] = chainIDs
	e.order = append(e.order, id)
	for _, cid := range chainIDs {
		e.chainTargets[cid] = true
	}
}

// Has reports whether a template with the given ID has been registered.
func (e *ChainExecutor) Has(id string) bool {
	if e == nil {
		return false
	}
	_, ok := e.chains[id]
	return ok
}

// IsEntrypoint reports whether id is NOT referenced as a chain target.
func (e *ChainExecutor) IsEntrypoint(id string) bool {
	if e == nil {
		return false
	}
	return !e.chainTargets[id]
}

// Entrypoints returns all registered IDs that are not chain targets,
// preserving insertion order.
func (e *ChainExecutor) Entrypoints() []string {
	if e == nil {
		return nil
	}
	var eps []string
	for _, id := range e.order {
		if e.IsEntrypoint(id) {
			eps = append(eps, id)
		}
	}
	return eps
}

// Execute walks the chain graph starting from startIDs.
// Use Entrypoints() as startIDs to run only non-chain-target templates.
// Safe to call on a nil receiver (no-op).
func (e *ChainExecutor) Execute(startIDs []string, fn ExecuteFunc) {
	if e == nil {
		return
	}
	executed := make(map[string]bool)
	if e.config.DepthFirst {
		for _, id := range startIDs {
			e.executeDFS(id, nil, fn, executed)
		}
	} else {
		e.executeBFS(startIDs, fn, executed)
	}
}

func (e *ChainExecutor) executeDFS(id string, vars map[string]interface{}, fn ExecuteFunc, executed map[string]bool) {
	if executed[id] || !e.Has(id) {
		return
	}
	executed[id] = true

	result := fn(id, vars)
	if result == nil {
		return
	}

	chainIDs := e.chains[id]
	if len(chainIDs) == 0 {
		return
	}

	var chainVars map[string]interface{}
	if e.config.PassVariables {
		chainVars = result.Vars
	}
	for _, cid := range chainIDs {
		e.executeDFS(cid, chainVars, fn, executed)
	}
}

type bfsItem struct {
	id   string
	vars map[string]interface{}
}

func (e *ChainExecutor) executeBFS(startIDs []string, fn ExecuteFunc, executed map[string]bool) {
	current := make([]bfsItem, len(startIDs))
	for i, id := range startIDs {
		current[i] = bfsItem{id: id}
	}

	for len(current) > 0 {
		var next []bfsItem
		for _, it := range current {
			if executed[it.id] || !e.Has(it.id) {
				continue
			}
			executed[it.id] = true

			var vars map[string]interface{}
			if e.config.PassVariables {
				vars = it.vars
			}
			result := fn(it.id, vars)
			if result == nil {
				continue
			}

			var chainVars map[string]interface{}
			if e.config.PassVariables {
				chainVars = result.Vars
			}
			for _, cid := range e.chains[it.id] {
				if !executed[cid] {
					next = append(next, bfsItem{id: cid, vars: chainVars})
				}
			}
		}
		current = next
	}
}
