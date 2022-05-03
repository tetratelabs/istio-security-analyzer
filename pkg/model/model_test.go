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

package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIstioRelease(t *testing.T) {
	testCases := []struct {
		input   string
		wantErr bool
		release IstioRelease
	}{
		{
			input: "1.11.1",
			release: IstioRelease{
				Major: 11,
				Minor: 1,
			},
		},
		{
			input: "1.4.0",
			release: IstioRelease{
				Major: 4,
				Minor: 0,
			},
		},
		{
			input:   "foo",
			wantErr: true,
		},
		{
			input:   "a.b.c",
			wantErr: true,
		},
		{
			input:   "2.1.1",
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			r, e := istioReleaseFromString(tc.input)
			if tc.wantErr {
				require.Error(t, e)
			} else {
				require.Equal(t, tc.release, r)
			}
		})
	}
}

func TestParseReleaseRange(t *testing.T) {
	testCases := []struct {
		input        string
		wantErr      bool
		releaseRange ReleaseRange
	}{
		{
			input: "1.11.1",
			releaseRange: ReleaseRange{
				RangeType:  ParticularType,
				Particular: IstioRelease{Major: 11, Minor: 1},
			},
		},
		{
			input: "1.12.1-1.12.6",
			releaseRange: ReleaseRange{
				RangeType: IntervalType,
				Start:     IstioRelease{Major: 12, Minor: 1},
				End:       IstioRelease{Major: 12, Minor: 6},
			},
		},
		{
			input: "-1.12.6",
			releaseRange: ReleaseRange{
				RangeType: IntervalType,
				End:       IstioRelease{Major: 12, Minor: 6},
			},
		},
		{
			input:   "invalid",
			wantErr: true,
		},
		{
			input:   "a-b",
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			r, e := IstioReleaseRangeFromString(tc.input)
			if tc.wantErr {
				require.Error(t, e)
			} else {
				require.Equal(t, r, tc.releaseRange)
			}
		})
	}
}
