package audit

import "testing"

func TestChainTableNames(t *testing.T) {
	if (AuditPending{}).TableName() != "mxid_audit_pending" {
		t.Fatal("AuditPending table name")
	}
	if (AuditEntry{}).TableName() != "mxid_audit_entry" {
		t.Fatal("AuditEntry table name")
	}
	if (ChainHead{}).TableName() != "mxid_audit_chain_head" {
		t.Fatal("ChainHead table name")
	}
}
