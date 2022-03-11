package parser

import (
	"fmt"
	"io/ioutil"
	"testing"

	istiosec "istio.io/api/security/v1beta1"
)

func TestParseFile(t *testing.T) {
	testCases := []struct {
		name string
		file string
	}{
		{
			name: "authz",
			file: "authz.yaml",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := ioutil.ReadFile("testdata/authz.yaml")
			if err != nil {
				t.Errorf("failed to read the config file: %v", err)
				return
			}
			c, err := decodeConfigYAML(string(b))
			if err != nil {
				t.Errorf("failed to parse, error %v", err)
			}
			for _, cc := range c {
				ok, f := (cc.Spec).(*istiosec.AuthorizationPolicy)
				fmt.Printf("jianfeih conversion: %v, %v\n", ok, f)
			}
		})
	}
}
