package cve

import (
	"os"
	"testing"
)

// TODO: cover the test logic.
func TestFindVunerabilities(t *testing.T) {
}

func TestRefreshDatabase(t *testing.T) {
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
