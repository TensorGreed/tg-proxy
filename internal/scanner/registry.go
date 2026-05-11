// Package scanner provides the runtime registry for Scanner implementations.
// Built-in scanners live in subpackages (e.g. internal/scanner/pii); they
// satisfy the api.Scanner interface and register themselves with a Registry
// at startup via Registry.Register.
package scanner

import (
	"fmt"
	"sort"
	"sync"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

type Registry struct {
	mu       sync.RWMutex
	scanners map[string]api.Scanner
}

func NewRegistry() *Registry {
	return &Registry{scanners: make(map[string]api.Scanner)}
}

// Register adds s to the registry. Returns an error if the name is empty or
// already taken.
func (r *Registry) Register(s api.Scanner) error {
	if s == nil {
		return fmt.Errorf("scanner: nil scanner")
	}
	name := s.Name()
	if name == "" {
		return fmt.Errorf("scanner: empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.scanners[name]; ok {
		return fmt.Errorf("scanner: %q already registered", name)
	}
	r.scanners[name] = s
	return nil
}

// Get returns the scanner registered under name.
func (r *Registry) Get(name string) (api.Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scanners[name]
	return s, ok
}

// List returns all registered scanners, sorted by name for deterministic
// iteration order.
func (r *Registry) List() []api.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]api.Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
