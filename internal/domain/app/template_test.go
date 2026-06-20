// internal/domain/app/template_test.go
package app

import (
	"errors"
	"testing"
)

func TestTemplatesLoad(t *testing.T) {
	ts := Templates()
	if len(ts) == 0 {
		t.Fatalf("expected built-in templates, got 0")
	}
	var found bool
	for _, tpl := range ts {
		if tpl.Key == "feishu" {
			found = true
			if tpl.Protocol != ProtocolOIDC {
				t.Fatalf("feishu protocol = %q, want oidc", tpl.Protocol)
			}
		}
	}
	if !found {
		t.Fatalf("feishu template not loaded")
	}
}

func TestGetTemplate(t *testing.T) {
	if _, err := GetTemplate("feishu"); err != nil {
		t.Fatalf("GetTemplate(feishu): %v", err)
	}
	if _, err := GetTemplate("does-not-exist"); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("GetTemplate(miss) err = %v, want ErrTemplateNotFound", err)
	}
}
