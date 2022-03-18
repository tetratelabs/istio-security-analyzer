package model

import (
	"fmt"
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
	// Description is a human-readable summary of the CVE.
	Description string `yaml:"description,omitempty"`
	// [0, 10].
	ImpactScore float32   `yaml:"impactScore,omitempty"`
	Date        time.Time `yaml:"date,omitempty"`
	// TODO: think deeper on the appropriate way to represent the release set.
	// 1. Release vesion & release CVE can both happen at any time. Wording use "prior to 1.11".
	// TODO: consider make YAML format and the internal data structure different.
	// 1.7.8: {}, weird.
	// IstioReleases    map[string]struct{}
	AffectedReleases []ReleaseRange `yaml:"affectedReleases,omitempty"`
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
	Major string
	Minor string
}

func (r IstioRelease) String() string {
	return fmt.Sprintf("%v.%v", r.Major, r.Minor)
}

func (r IstioRelease) IsBefore(other IstioRelease) bool {
	if r.Major < other.Major {
		return true
	}
	if r.Major == other.Major {
		return r.Minor < other.Minor
	}
	return false
}

func (r IstioRelease) IsAfter(other IstioRelease) bool {
	return other.IsBefore(r)
}

func ParseRelease(s string) (error, IstioRelease) {
	out := IstioRelease{}
	elm := strings.Split(s, ".")
	if len(elm) != 3 {
		return fmt.Errorf("failed to parse release, expected x.y.z, got %v", s), out
	}
	// TODO(incfly): check the element is actual numeric.
	out.Major = fmt.Sprintf("%v.%v", elm[0], elm[1])
	out.Minor = elm[2]
	return nil, out
}

func (rs ReleaseRange) Include(r IstioRelease) bool {
	if rs.RangeType == ParticularType {
		return rs.Particular == r
	}
	return (r.IsAfter(rs.Start) || r == rs.Start) && (r.IsBefore(rs.End) || r == rs.End)
}

// SecurityReport contains a comprehensive summary of the scanning results.
type SecurityReport struct {
	IstioVersion   string
	Vunerabilities []*CVEEntry
	ConfigWarnings []string
}
