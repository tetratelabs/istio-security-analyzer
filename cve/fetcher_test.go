package cve

import "testing"

func TestFetch(t *testing.T) {
	if err := FetchIstioPage(); err != nil {
		t.Error(err)
	}
}
