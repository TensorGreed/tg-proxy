// Package redactor provides the runtime registry for Redactor implementations.
// Built-in redactors live in subpackages (e.g. internal/redactor/mask) and
// satisfy api.Redactor. Unlike scanners, only one redactor is active per
// pipeline; the registry exists so users can swap implementations by name in
// configuration.
package redactor

import (
	"fmt"
	"sort"
	"sync"

	"github.com/TensorGreed/tg-proxy/pkg/api"
)

type Registry struct {
	mu        sync.RWMutex
	redactors map[string]api.Redactor
}

func NewRegistry() *Registry {
	return &Registry{redactors: make(map[string]api.Redactor)}
}

func (r *Registry) Register(d api.Redactor) error {
	if d == nil {
		return fmt.Errorf("redactor: nil redactor")
	}
	name := d.Name()
	if name == "" {
		return fmt.Errorf("redactor: empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.redactors[name]; ok {
		return fmt.Errorf("redactor: %q already registered", name)
	}
	r.redactors[name] = d
	return nil
}

func (r *Registry) Get(name string) (api.Redactor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.redactors[name]
	return d, ok
}

func (r *Registry) List() []api.Redactor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]api.Redactor, 0, len(r.redactors))
	for _, d := range r.redactors {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
