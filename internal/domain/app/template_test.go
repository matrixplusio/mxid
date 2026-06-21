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

func TestCatalogCoverage(t *testing.T) {
	ts := Templates()
	if len(ts) < 9 {
		t.Fatalf("catalog has %d templates, want >= 9", len(ts))
	}
	want := map[string]bool{
		"feishu": false, "dingtalk": false, "wecom": false, "gitlab": false,
		"grafana": false, "jenkins": false, "jira": false, "confluence": false,
		"jumpserver": false,
	}
	protos := map[string]bool{}
	for _, tpl := range ts {
		if _, ok := want[tpl.Key]; ok {
			want[tpl.Key] = true
		}
		protos[tpl.Protocol] = true
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("template %q missing from catalog", k)
		}
	}
	for _, p := range []string{ProtocolOIDC, ProtocolSAML, ProtocolCAS} {
		if !protos[p] {
			t.Fatalf("catalog has no %s template", p)
		}
	}
}

func TestJumpServerIsCAS(t *testing.T) {
	tpl, err := GetTemplate("jumpserver")
	if err != nil {
		t.Fatalf("jumpserver: %v", err)
	}
	if tpl.Protocol != ProtocolCAS {
		t.Fatalf("jumpserver protocol = %q, want cas (community edition only ships CAS)", tpl.Protocol)
	}
	if tpl.SubjectStrategy != "username" {
		t.Fatalf("jumpserver subject_strategy = %q, want username (avoid numeric principal)", tpl.SubjectStrategy)
	}
}
