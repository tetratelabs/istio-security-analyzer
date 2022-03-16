package model

import "testing"

// func TestRender(t *testing.T) {
// 	if _, err := RenderHTML(); err != nil {
// 		t.Fatal(err)
// 	}
// }

// go test -v ./model
// curl localhost:8080/ --output -
// TODO(here): why binary output?
func TestHTTP(t *testing.T) {
	t.Logf("Starting the http server on port 8080...")
	StartAll()
}
