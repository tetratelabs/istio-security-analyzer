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
	ParticularType ReleaseRangeType = "particular"
	IntervalType   ReleaseRangeType = "range"
)

var (
	releaseFormatError = errors.New("invalid release string, expect 1.<numberic>.<numeric>, such as 1.11.2")
	rangeFormatError   = errors.New("invalid release range format, valid choices: 1.13.0, 1.12.0-1.12.6, -1.12.3")
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

	// ReleaseRanges is the string of the affected release range, intended to be edited by human.
	// Example "1.12.1", "1.12.1-1.13.2;1.10.0;-1.5.3"
	ReleaseRanges []string `yaml:"releases,omitempty"`

	// internal representation of the release range after parisng the `ReleaseRanges` above, intented
	// to be consumed by program.
	affectedReleases []ReleaseRange
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

func istioReleaseFromString(input string) (IstioRelease, error) {
	out := IstioRelease{}
	elems := strings.Split(input, ".")
	if len(elems) != 3 {
		return out, releaseFormatError
	}
	vs := make([]int, 3)
	for i, e := range elems {
		var err error
		vs[i], err = strconv.Atoi(e)
		if err != nil {
			return out, releaseFormatError
		}
	}
	if vs[0] != 1 {
		return out, releaseFormatError
	}
	return IstioRelease{
		Major: vs[1],
		Minor: vs[2],
	}, nil
}

func IstioReleaseRangeFromString(input string) (ReleaseRange, error) {
	out := ReleaseRange{}
	// handle as single release.
	if !strings.Contains(input, "-") {
		r, e := istioReleaseFromString(input)
		if e != nil {
			return out, rangeFormatError
		}
		return ReleaseRange{
			RangeType:  ParticularType,
			Particular: r,
		}, nil
	}
	elems := strings.Split(input, "-")
	if len(elems) > 2 {
		return out, rangeFormatError
	}
	out.RangeType = IntervalType
	if elems[0] != "" {
		r, e := istioReleaseFromString(elems[0])
		if e != nil {
			return out, rangeFormatError
		}
		out.Start = r
	}
	if elems[1] != "" {
		r, e := istioReleaseFromString(elems[1])
		if e != nil {
			return out, rangeFormatError
		}
		out.End = r
	}
	return out, nil
}

func (rs ReleaseRange) Include(r IstioRelease) bool {
	if rs.RangeType == ParticularType {
		return rs.Particular == r
	}
	return (r.AfterOrEquals(rs.Start) || r == rs.Start) && (r.BeforeOrEquals(rs.End) || r == rs.End)
}

// securityReportParams contains a comprehensive summary of the scanning results.
type securityReportParams struct {
	IstioVersion              string
	DistrolessIssue           string
	Vunerabilities            []*CVEEntry
	ConfigWarnings            []string
	ConfigScannedCountByGroup map[string]int
	NetworkingConfigCount     int
	SecurityConfigCount       int
}

// WorkloadReport contains the scanning report for workload
type WorkloadReport struct {
	// Pod id
	PodID string `json:"PodID"`
	// Cluster name in which pod is running
	Cluster string `json:"Cluster"`
	// A comma separated list of inbound ports to be excluded from redirection to Envoy
	ExcludeInboundPorts []string `json:"ExcludeInboundPorts"`
	// A comma separated list of outbound ports to be excluded from redirection to Envoy
	ExcludeOutboundPorts []string `json:"ExcludeOutboundPorts"`
	// Service account used by pod
	ServiceAccount string `json:"ServiceAccount"`
}
