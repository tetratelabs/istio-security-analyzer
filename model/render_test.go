package model

import "testing"

func TestRender(t *testing.T) {
	if err := RenderHTML(); err != nil {
		t.Fatal(err)
	}
}
