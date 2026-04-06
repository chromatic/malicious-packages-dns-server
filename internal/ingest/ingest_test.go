package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/chromatic/malicious-packages-dns-server/internal/ingest"
	"github.com/chromatic/malicious-packages-dns-server/internal/store"
)

// fixtureDir points at the repo-level testdata directory.
const fixtureDir = "../../testdata"

func TestIngestExactVersions(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.bolt")
	if err := ingest.Build(fixtureDir, out); err != nil {
		t.Fatalf("Build: %v", err)
	}

	s, err := store.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// MAL-2024-001 has exact versions 1.0.0 and 1.0.1 for pypi/malicious-pkg
	r, ok := s.Lookup("pypi", "malicious-pkg", "1.0.0")
	if !ok {
		t.Fatal("expected version hit for 1.0.0")
	}
	if r.OSVID != "MAL-2024-001" {
		t.Errorf("OSVID = %q, want MAL-2024-001", r.OSVID)
	}
	if r.MatchLevel != "version" {
		t.Errorf("MatchLevel = %q, want version", r.MatchLevel)
	}

	r, ok = s.Lookup("pypi", "malicious-pkg", "1.0.1")
	if !ok {
		t.Fatal("expected version hit for 1.0.1")
	}
	if r.OSVID != "MAL-2024-001" {
		t.Errorf("OSVID = %q, want MAL-2024-001", r.OSVID)
	}

	_, ok = s.Lookup("pypi", "malicious-pkg", "2.0.0")
	if ok {
		t.Fatal("expected miss for unlisted version 2.0.0")
	}
}

func TestIngestEcosystemRangeBecomesPackageBlock(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.bolt")
	if err := ingest.Build(fixtureDir, out); err != nil {
		t.Fatalf("Build: %v", err)
	}

	s, err := store.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// MAL-2024-003 has an ECOSYSTEM range → package-level block
	r, ok := s.Lookup("npm", "@scope/scoped-evil", "1.2.3")
	if !ok {
		t.Fatal("expected package hit for ecosystem-range entry")
	}
	if r.MatchLevel != "package" {
		t.Errorf("MatchLevel = %q, want package", r.MatchLevel)
	}
	if r.OSVID != "MAL-2024-003" {
		t.Errorf("OSVID = %q, want MAL-2024-003", r.OSVID)
	}
}

func TestIngestNormalisesEcosystemCase(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.bolt")
	if err := ingest.Build(fixtureDir, out); err != nil {
		t.Fatalf("Build: %v", err)
	}

	s, err := store.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Fixture uses "PyPI" (mixed case); lookup should work with lowercase.
	_, ok := s.Lookup("pypi", "malicious-pkg", "1.0.0")
	if !ok {
		t.Fatal("expected hit with lowercased ecosystem")
	}
}

func TestIngestMultiPairSemverRanges(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.bolt")
	if err := ingest.Build(fixtureDir, out); err != nil {
		t.Fatalf("Build: %v", err)
	}

	s, err := store.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// MAL-2024-004 has two (introduced, fixed) pairs: [1.0.0, 1.2.0) and [2.0.0, 2.1.0)
	for _, tc := range []struct {
		ver  string
		want bool
	}{
		{"1.0.0", true},  // at first introduced
		{"1.1.0", true},  // inside first range
		{"1.2.0", false}, // at first fixed — excluded
		{"1.9.0", false}, // between ranges
		{"2.0.0", true},  // at second introduced
		{"2.0.5", true},  // inside second range
		{"2.1.0", false}, // at second fixed — excluded
		{"3.0.0", false}, // above both ranges
	} {
		_, ok := s.Lookup("npm", "multi-range-pkg", tc.ver)
		if ok != tc.want {
			t.Errorf("Lookup(npm, multi-range-pkg, %s) = %v, want %v", tc.ver, ok, tc.want)
		}
	}
}
