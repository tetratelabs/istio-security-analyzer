package parser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFile(t *testing.T) {
	testCases := []struct {
		name       string
		file       string
		errMessage []string
	}{
		{
			name: "authz",
			file: "testdata/authz.yaml",
		},
		{
			name:       "non exists",
			file:       "authz-noexists.yaml",
			errMessage: []string{"not a valid path"},
		},
		{
			name:       "dr tls",
			file:       "testdata/dr-tls.yaml",
			errMessage: []string{"subjectAltNames is not set."},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errs := CheckFileSystem(tc.file)
			require.Equal(t, len(tc.errMessage), len(errs))
			for ind, msg := range tc.errMessage {
				require.Contains(t, errs[ind].Error(), msg)
			}
		})
	}
}
