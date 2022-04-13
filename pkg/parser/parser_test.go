// Copyright 2022 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
