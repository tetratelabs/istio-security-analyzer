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
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFindVunerabilities(t *testing.T) {
	testCases := []struct {
		istioRelease string
		cves         []string
	}{
		// Verified.
		{
			istioRelease: "1.13.1",
			cves: []string{
				"ISTIO-SECURITY-2022-004",
			},
		},
		// Verified.
		{
			istioRelease: "1.12.1",
			cves: []string{
				"ISTIO-SECURITY-2022-004",
				"ISTIO-SECURITY-2022-003",
				"ISTIO-SECURITY-2022-002",
				"ISTIO-SECURITY-2022-001",
			},
		},
		// Verified.
		{
			istioRelease: "1.9.9",
			cves: []string{
				"ISTIO-SECURITY-2022-004",
				"ISTIO-SECURITY-2022-003",
			},
		},
		// Verified.
		{
			istioRelease: "1.9.1",
			cves: []string{
				"ISTIO-SECURITY-2022-004",
				"ISTIO-SECURITY-2022-003",
				"ISTIO-SECURITY-2021-005",
				"ISTIO-SECURITY-2021-006",
				"ISTIO-SECURITY-2021-007",
				"ISTIO-SECURITY-2021-008",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.istioRelease, func(t *testing.T) {
			cves := FindVunerabilities(tc.istioRelease)
			got := []string{}
			for _, c := range cves {
				got = append(got, c.DisclosureID)
			}
			sort.Strings(got)
			sort.Strings(tc.cves)
			if diff := cmp.Diff(got, tc.cves); diff != "" {
				t.Errorf("unexpected CVE lists\ngot %v\nwant %v\ndiff\n%v\n", got, tc.cves, diff)
			}
		})
	}
}

func TestRefreshDatabase(t *testing.T) {
	refresh := os.Getenv("REFRESH_CVEDB")
	if refresh != "true" {
		t.Skipf("Skip refresh the database, only if REFRESH_CVEDB=true, got %v", refresh)
	}
	e, err := FetchIstioPage()
	if err != nil {
		t.Fatal(err)
	}
	// TODO: this should really be merge with existing data instead of override.
	// New entries are added, existing entries are ignored.
	if err := SaveDatabase(e, "./database.yaml"); err != nil {
		t.Error(err)
	}

}
