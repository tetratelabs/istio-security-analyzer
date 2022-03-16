package cve

import "testing"

func TestFetch(t *testing.T) {
	entries, err := FetchIstioPage()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("entries\n%v", entries)
}

// TODO: implement the test logic.
func TestFindVunerabilities(t *testing.T) {
}

func TestSaveYAML(t *testing.T) {
	e := BuildEntryInfoForTest()
	if err := SaveDatabase(e, "/tmp/foo.yaml"); err != nil {
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
