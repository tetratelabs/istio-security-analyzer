package model

import (
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

func ParseRelease(s string) (error, IstioRelease) {
	out := IstioRelease{}
	elm := strings.Split(s, ".")
	if len(elm) != 3 {
		return fmt.Errorf("failed to parse release, expected x.y.z, got %v", s), out
	}
	major, err := strconv.Atoi(elm[1])
	if err != nil {
		return err, out
	}
	minor, err := strconv.Atoi(elm[2])
	if err != nil {
		return err, out
	}
	return nil, IstioRelease{Major: major, Minor: minor}
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
