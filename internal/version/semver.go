package version

import (
	"strings"

	"github.com/blang/semver/v4"
)

// Range describes a single SEMVER vulnerability range.
type Range struct {
	Ecosystem  string
	Name       string
	Introduced string // semver string, e.g. "1.0.0"
	Fixed      string // semver string; empty means no upper bound
	OSVID      string
}

// Result is returned by RangeSet.Lookup on a hit.
type Result struct {
	OSVID string
}

// RangeSet holds a collection of SEMVER ranges for query-time evaluation.
type RangeSet struct {
	ranges []parsedRange
}

type parsedRange struct {
	ecosystem  string
	name       string
	introduced semver.Version
	fixed      semver.Version
	hasFixed   bool
	osvID      string
}

// NewRangeSet returns an empty RangeSet.
func NewRangeSet() *RangeSet {
	return &RangeSet{}
}

// Add parses and stores a Range. Ranges with unparseable introduced versions are silently dropped.
func (rs *RangeSet) Add(r Range) {
	introduced, err := semver.ParseTolerant(r.Introduced)
	if err != nil {
		return
	}
	pr := parsedRange{
		ecosystem:  strings.ToLower(r.Ecosystem),
		name:       strings.ToLower(r.Name),
		introduced: introduced,
		osvID:      r.OSVID,
	}
	if r.Fixed != "" {
		fixed, err := semver.ParseTolerant(r.Fixed)
		if err == nil {
			pr.fixed = fixed
			pr.hasFixed = true
		}
	}
	rs.ranges = append(rs.ranges, pr)
}

// Lookup returns (Result, true) if version falls within any stored range for ecosystem+name.
func (rs *RangeSet) Lookup(ecosystem, name, ver string) (Result, bool) {
	v, err := semver.ParseTolerant(ver)
	if err != nil {
		return Result{}, false
	}
	eco := strings.ToLower(ecosystem)
	n := strings.ToLower(name)

	for _, r := range rs.ranges {
		if r.ecosystem != eco || r.name != n {
			continue
		}
		if v.LT(r.introduced) {
			continue
		}
		if r.hasFixed && v.GTE(r.fixed) {
			continue
		}
		return Result{OSVID: r.osvID}, true
	}
	return Result{}, false
}

// LookupVersion returns (Result, true) if ver falls within any range in the set,
// without filtering by ecosystem or name. Use this when the set has already been
// narrowed to a single package (e.g. retrieved by package hash from bbolt).
func (rs *RangeSet) LookupVersion(ver string) (Result, bool) {
	v, err := semver.ParseTolerant(ver)
	if err != nil {
		return Result{}, false
	}
	for _, r := range rs.ranges {
		if v.LT(r.introduced) {
			continue
		}
		if r.hasFixed && v.GTE(r.fixed) {
			continue
		}
		return Result{OSVID: r.osvID}, true
	}
	return Result{}, false
}
