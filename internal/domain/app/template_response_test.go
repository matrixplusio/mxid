package app

import "testing"

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
}
