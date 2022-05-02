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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ReleaseRangeType string

const (
	ParticularType     ReleaseRangeType = "particular"
	IntervalType       ReleaseRangeType = "range"
	releaseFormatError                  = "invalid release string, expect 1.<numberic>.<numeric>, such as 1.11.2"
	rangeFormatError                    = "invalid release range format, valid choices: 1.13.0, 1.12.0-1.12.6, -1.12.3"
)

type CVEEntry struct {
	// DisclosureID uniquely identifies a single disclosure. For example, "ISTIO-SECURITY-2022-004".
	DisclosureID string `yaml:"disclosureID,omitempty"`
	// URL is the link to the corresponding Istio CVE page.
	URL string
	// Description is a human-readable summary of the CVE.
	Description string `yaml:"description,omitempty"`
	// [0, 10].
	ImpactScore float32   `yaml:"impactScore,omitempty"`
	Date        time.Time `yaml:"date,omitempty"`
	// TODO: think deeper on the appropriate way to represent the release set.
	// 1. Release vesion & release CVE can both happen at any time. Wording use "prior to 1.11".
	AffectedReleases []ReleaseRange `yaml:"affectedReleases,omitempty"`
	// "1.12.1", "1.12.1-1.13.2;1.10.0;-1.5.3"
	ReleaseRange string `yaml:"releases,omitempty"`
}

// IstioControlPlaneReport contains relevant issues for Istio Control Plane.
// For example, CVE of the Istio Control Plane; Should consider distroless
// image.
type IstioControlPlaneReport struct {
	IstioVersion string
	// DistrolessIssue specifies the potential upgradable distroless if possible.
	DistrolessIssue error
}

// ReleaseRange represents a single or a range of Istio releases.
type ReleaseRange struct {
	RangeType ReleaseRangeType
	// Start a particular release, included if specified.
	Start IstioRelease `yaml:"start,omitempty"`
	// End a particular release, included if specified.
	End IstioRelease `yaml:"end,omitempty"`

	// Particulr release.
	Particular IstioRelease `yaml:"particular,omitempty"`
}

type IstioRelease struct {
	// Example, 9 for 1.9.2 release.
	Major int
	// Example, 2 for 1.9.2 release.
	Minor int
}

func (r IstioRelease) String() string {
	return fmt.Sprintf("1.%v.%v", r.Major, r.Minor)
}

func (r IstioRelease) BeforeOrEquals(other IstioRelease) bool {
	if r.Major < other.Major {
		return true
	}
	if r.Major == other.Major {
		return r.Minor < other.Minor
	}
	return r.Major == other.Major && r.Minor == other.Minor
}

func (r IstioRelease) AfterOrEquals(other IstioRelease) bool {
	return other.BeforeOrEquals(r)
}

func IstioReleaseFromString(input string) (error, IstioRelease) {
	out := IstioRelease{}
	elems := strings.Split(input, ".")
	if len(elems) != 3 {
		return errors.New(releaseFormatError), out
	}
	vs := make([]int, 3)
	for i, e := range elems {
		var err error
		vs[i], err = strconv.Atoi(e)
		if err != nil {
			return errors.New(releaseFormatError), out
		}
	}
	if vs[0] != 1 {
		return errors.New(releaseFormatError), out
	}
	return nil, IstioRelease{
		Major: vs[1],
		Minor: vs[2],
	}
}

func IstioReleaseRangeFromString(input string) (error, ReleaseRange) {
	out := ReleaseRange{}
	// handle as single release.
	if !strings.Contains(input, "-") {
		e, r := IstioReleaseFromString(input)
		if e != nil {
			return errors.New(rangeFormatError), out
		}
		return nil, ReleaseRange{
			RangeType: ParticularType,
			Start:     r,
			End:       r,
		}
	}
	elems := strings.Split(input, "-")
	if len(elems) > 2 {
		return errors.New(rangeFormatError), out
	}
	out.RangeType = IntervalType
	if elems[0] != "" {
		e, r := IstioReleaseFromString(elems[0])
		if e != nil {
			return errors.New(rangeFormatError), out
		}
		out.Start = r
	}
	if elems[1] != "" {
		e, r := IstioReleaseFromString(elems[1])
		if e != nil {
			return errors.New(rangeFormatError), out
		}
		out.End = r
	}
	return nil, out
}

func (rs ReleaseRange) Include(r IstioRelease) bool {
	if rs.RangeType == ParticularType {
		return rs.Particular == r
	}
	return (r.AfterOrEquals(rs.Start) || r == rs.Start) && (r.BeforeOrEquals(rs.End) || r == rs.End)
}

// securityReportParams contains a comprehensive summary of the scanning results.
type securityReportParams struct {
	IstioVersion    string
	DistrolessIssue string
	Vunerabilities  []*CVEEntry
	ConfigWarnings  []string
}
