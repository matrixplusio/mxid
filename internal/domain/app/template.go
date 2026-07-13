// internal/domain/app/template.go
package app

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

//go:embed templates/*.json
var templateFS embed.FS

// ErrTemplateNotFound is returned by GetTemplate for an unknown key.
var ErrTemplateNotFound = errors.New("template not found")

// TemplateField is a single differential input the create wizard asks for
// after a template is chosen (the rest is pre-filled from Defaults).
type TemplateField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Type        string `json:"type"` // "text" | "textarea"
	Placeholder string `json:"placeholder,omitempty"`
	// Target tells the wizard where the value goes:
	//   "redirect_uris"           -> top-level redirect URIs (newline/comma split)
	//   "home_url"                -> top-level home URL
	//   "protocol_config.<name>"  -> a key inside protocol_config
	Target string `json:"target"`
}

// Template is a declarative app-onboarding preset. It NEVER contains secrets.
type Template struct {
	Key             string          `json:"key"`
	Name            string          `json:"name"`
	Icon            string          `json:"icon,omitempty"`
	Category        string          `json:"category"`
	Protocol        string          `json:"protocol"`
	ClientType      string          `json:"client_type"`
	SubjectStrategy string          `json:"subject_strategy,omitempty"`
	Description     string          `json:"description,omitempty"`
	DocMD           string          `json:"doc_md,omitempty"`
	Defaults        map[string]any  `json:"defaults,omitempty"` // merged into protocol_config
	Fields          []TemplateField `json:"fields,omitempty"`
}

var (
	loadOnce  sync.Once
	loaded    []Template
	loadedIdx map[string]Template
	loadErr   error
)

// secretLikeKeys are rejected in Defaults — templates must stay declarative.
var secretLikeKeys = map[string]bool{
	"client_secret": true,
	"secret":        true,
	"password":      true,
}

func validProtocol(p string) bool {
	return p == ProtocolOIDC || p == ProtocolSAML || p == ProtocolCAS || p == ProtocolForm
}

func loadTemplates() {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		loadErr = fmt.Errorf("read templates dir: %w", err)
		return
	}
	idx := make(map[string]Template, len(entries))
	out := make([]Template, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			loadErr = fmt.Errorf("read %s: %w", e.Name(), err)
			return
		}
		var tpl Template
		if err := json.Unmarshal(b, &tpl); err != nil {
			loadErr = fmt.Errorf("parse %s: %w", e.Name(), err)
			return
		}
		if tpl.Key == "" || tpl.Name == "" {
			loadErr = fmt.Errorf("%s: key and name are required", e.Name())
			return
		}
		if !validProtocol(tpl.Protocol) {
			loadErr = fmt.Errorf("%s: invalid protocol %q", e.Name(), tpl.Protocol)
			return
		}
		for k := range tpl.Defaults {
			if secretLikeKeys[k] {
				loadErr = fmt.Errorf("%s: defaults must not contain secret key %q", e.Name(), k)
				return
			}
		}
		if _, dup := idx[tpl.Key]; dup {
			loadErr = fmt.Errorf("duplicate template key %q", tpl.Key)
			return
		}
		idx[tpl.Key] = tpl
		out = append(out, tpl)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	loaded, loadedIdx = out, idx
}

func ensureLoaded() {
	loadOnce.Do(loadTemplates)
}

// Templates returns all built-in templates, sorted by category then name.
// Panics if any embedded template is malformed (fail-fast at boot).
func Templates() []Template {
	ensureLoaded()
	if loadErr != nil {
		panic(loadErr)
	}
	return loaded
}

// GetTemplate returns one template by key, or ErrTemplateNotFound.
func GetTemplate(key string) (Template, error) {
	ensureLoaded()
	if loadErr != nil {
		return Template{}, loadErr
	}
	tpl, ok := loadedIdx[key]
	if !ok {
		return Template{}, ErrTemplateNotFound
	}
	return tpl, nil
}
