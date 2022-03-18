package cve

import (
	"os"
	"testing"
)

func TestFetch(t *testing.T) {
	entries, err := FetchIstioPage()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("entries\n%v", entries)
}

// TODO: cover the test logic.
func TestFindVunerabilities(t *testing.T) {
}

func TestSaveYAML(t *testing.T) {
	refresh := os.Getenv("REFRESH_CVEDB")
	if refresh != "true" {
		t.Skipf("Skip refresh the database, only if REFRESH_CVEDB=true, got %v", refresh)
	}
	// e, err := FetchIstioPage()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	e := BuildEntryInfoForTest()
	if err := SaveDatabase(e, "./database.yaml"); err != nil {
		t.Error(err)
	}
}

func TestLoadYAML(t *testing.T) {
	db, err := LoadDatabase("/tmp/foo.yaml")
	if err != nil {
		t.Error(err)
	}
	t.Logf("db %v", db)
}
