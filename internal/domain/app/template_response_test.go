package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToTemplateListItems(t *testing.T) {
	in := []Template{{
		Key: "feishu", Name: "飞书", Icon: "x", Category: "collaboration",
		Protocol: "oidc", Description: "desc",
		DocMD: "SHOULD NOT LEAK", // detail-only field must be absent from list items
	}}
	out := ToTemplateListItems(in)
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].Key != "feishu" || out[0].Protocol != "oidc" || out[0].Category != "collaboration" {
		t.Fatalf("unexpected item: %+v", out[0])
	}
	b, err := json.Marshal(out[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "doc_md") || strings.Contains(string(b), "SHOULD NOT LEAK") {
		t.Fatalf("detail-only field leaked into list item: %s", b)
	}
}
