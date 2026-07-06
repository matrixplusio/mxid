package audit

import "testing"

func TestAuditAnchorTableName(t *testing.T) {
	if (AuditAnchor{}).TableName() != "mxid_audit_anchor" {
		t.Fatal("wrong table name")
	}
}
