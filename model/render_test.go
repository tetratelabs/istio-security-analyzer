package model

import "testing"

// func TestRender(t *testing.T) {
// 	if _, err := RenderReport(&SecurityReport{}); err != nil {
// 		t.Fatal(err)
// 	}
// }

func TestValidateDatabase(t *testing.T) {
	db, err := LoadDatabase("./database.yaml")
	if err != nil {
		t.Error(err)
	}
	for ind, e := range db {
		t.Logf("Validating %v/%v, disclosure id %v", ind+1, len(db), e.DisclosureID)
		if e.DisclosureID == "" {
			t.Fatalf("disclosure ID must be non empty")
		}
		if len(e.AffectedReleases) == 0 {
			t.Fatalf("release must be non empty")
		}
	}
}
