package version_test

import (
	"testing"

	"github.com/chromatic/malicious-packages-dns/internal/version"
)

func TestSemverRangeHit(t *testing.T) {
	rs := version.NewRangeSet()
	rs.Add(version.Range{
		Ecosystem:  "npm",
		Name:       "evil-package",
		Introduced: "1.0.0",
		Fixed:      "1.2.0",
		OSVID:      "MAL-2024-002",
	})

	r, ok := rs.Lookup("npm", "evil-package", "1.1.0")
	if !ok {
		t.Fatal("expected hit for 1.1.0 in [1.0.0, 1.2.0)")
	}
	if r.OSVID != "MAL-2024-002" {
		t.Errorf("OSVID = %q, want MAL-2024-002", r.OSVID)
	}
}

func TestSemverRangeExcludesFixed(t *testing.T) {
	rs := version.NewRangeSet()
	rs.Add(version.Range{
		Ecosystem:  "npm",
		Name:       "evil-package",
		Introduced: "1.0.0",
		Fixed:      "1.2.0",
		OSVID:      "MAL-2024-002",
	})

	_, ok := rs.Lookup("npm", "evil-package", "1.2.0")
	if ok {
		t.Fatal("fixed version 1.2.0 should not be a hit")
	}
}

func TestSemverRangeMissBeforeIntroduced(t *testing.T) {
	rs := version.NewRangeSet()
	rs.Add(version.Range{
		Ecosystem:  "npm",
		Name:       "evil-package",
		Introduced: "1.0.0",
		Fixed:      "1.2.0",
		OSVID:      "MAL-2024-002",
	})

	_, ok := rs.Lookup("npm", "evil-package", "0.9.9")
	if ok {
		t.Fatal("version before introduced should not be a hit")
	}
}

func TestSemverRangeNoUpperBound(t *testing.T) {
	rs := version.NewRangeSet()
	rs.Add(version.Range{
		Ecosystem:  "npm",
		Name:       "evil-package",
		Introduced: "1.0.0",
		Fixed:      "", // no upper bound
		OSVID:      "MAL-2024-002",
	})

	r, ok := rs.Lookup("npm", "evil-package", "99.0.0")
	if !ok {
		t.Fatal("expected hit with no upper bound")
	}
	if r.OSVID != "MAL-2024-002" {
		t.Errorf("OSVID = %q, want MAL-2024-002", r.OSVID)
	}
}

func TestSemverRangeWrongPackageMiss(t *testing.T) {
	rs := version.NewRangeSet()
	rs.Add(version.Range{
		Ecosystem:  "npm",
		Name:       "evil-package",
		Introduced: "1.0.0",
		Fixed:      "1.2.0",
		OSVID:      "MAL-2024-002",
	})

	_, ok := rs.Lookup("npm", "other-package", "1.1.0")
	if ok {
		t.Fatal("different package should not match")
	}
}
