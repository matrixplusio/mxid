//go:build eesmoke

// EE garble smoke. Compiled and run under `garble` (see `make ee-smoke`) so it
// reproduces the field-name obfuscation that only the EE binary carries. It
// exercises the reflection-driven GORM scan paths that broke in prod — the
// access-subject resolver renders "(未知)" and portal apps vanish when a scan
// struct lacks explicit `gorm:"column:..."` tags, because garble renames the
// Go field and GORM can no longer map the column.
//
// Being an in-package test it can reach the unexported resolver. It seeds a
// throwaway row, asserts the value round-trips NON-EMPTY, and cleans up.
//
// Run indirectly: `make ee-smoke` (builds under garble in a go1.26 container,
// points MXID_REPRO_DSN at a Postgres with migrations applied).
package app

import (
	"os"
	"testing"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	smokeTenantID = int64(1)
	smokeGroupID  = int64(9000000000000000123)
	smokeGroupNm  = "eesmoke-grp"
	smokeGroupCd  = "eesmoke_grp_9123"
)

func openSmokeDB(t *testing.T) *gorm.DB {
	dsn := os.Getenv("MXID_REPRO_DSN")
	if dsn == "" {
		t.Skip("MXID_REPRO_DSN not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

// TestEESmokeSubjectResolver is the direct regression for the "(未知)" prod bug:
// under garble, an untagged scan struct returns an empty subject name. With the
// resolver's scan structs tagged, a live group must resolve to its real name.
func TestEESmokeSubjectResolver(t *testing.T) {
	db := openSmokeDB(t)

	db.Exec(`DELETE FROM mxid_app_access_policy WHERE subject_type='group' AND subject_id=?`, smokeGroupID)
	db.Exec(`DELETE FROM mxid_user_group WHERE id=?`, smokeGroupID)
	if err := db.Exec(
		`INSERT INTO mxid_user_group (id, tenant_id, name, code) VALUES (?,?,?,?)`,
		smokeGroupID, smokeTenantID, smokeGroupNm, smokeGroupCd,
	).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM mxid_user_group WHERE id=?`, smokeGroupID) })

	r := newAccessSubjectResolver(&bootstrap.App{DB: db})
	name, code := r.Resolve(nil, appaccess.SubjectGroup, smokeGroupID)

	if name == "" || code == "" {
		t.Fatalf("GARBLE REGRESSION: resolver returned empty (name=%q code=%q) for a live group; "+
			"a GORM scan struct is missing gorm:\"column:...\" tags", name, code)
	}
	if name != smokeGroupNm || code != smokeGroupCd {
		t.Fatalf("resolver mismatch: name=%q code=%q want %q/%q", name, code, smokeGroupNm, smokeGroupCd)
	}
}
