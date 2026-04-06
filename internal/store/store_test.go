package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chromatic/malicious-packages-dns-server/internal/store"
	"github.com/chromatic/malicious-packages-dns-server/internal/version"
)

func TestLookupVersionHit(t *testing.T) {
	db := buildTestDB(t, map[string]string{
		"pypi:malicious-pkg:1.0.0": "MAL-2024-001",
		"pypi:malicious-pkg:1.0.1": "MAL-2024-001",
	}, nil)

	s, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r, ok := s.Lookup("pypi", "malicious-pkg", "1.0.0")
	if !ok {
		t.Fatal("expected hit, got miss")
	}
	if r.OSVID != "MAL-2024-001" {
		t.Errorf("OSVID = %q, want MAL-2024-001", r.OSVID)
	}
	if r.MatchLevel != "version" {
		t.Errorf("MatchLevel = %q, want version", r.MatchLevel)
	}
}

func TestLookupVersionMiss(t *testing.T) {
	db := buildTestDB(t, map[string]string{
		"pypi:malicious-pkg:1.0.0": "MAL-2024-001",
	}, nil)

	s, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, ok := s.Lookup("pypi", "malicious-pkg", "2.0.0")
	if ok {
		t.Fatal("expected miss, got hit")
	}
}

func TestLookupPackageHit(t *testing.T) {
	db := buildTestDB(t, nil, map[string]string{
		"npm:@scope/scoped-evil": "MAL-2024-003",
	})

	s, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r, ok := s.Lookup("npm", "@scope/scoped-evil", "9.9.9")
	if !ok {
		t.Fatal("expected hit, got miss")
	}
	if r.OSVID != "MAL-2024-003" {
		t.Errorf("OSVID = %q, want MAL-2024-003", r.OSVID)
	}
	if r.MatchLevel != "package" {
		t.Errorf("MatchLevel = %q, want package", r.MatchLevel)
	}
}

func TestLookupVersionBeatsPackage(t *testing.T) {
	db := buildTestDB(t,
		map[string]string{"pypi:pkg:1.0.0": "MAL-2024-001"},
		map[string]string{"pypi:pkg": "MAL-2024-001"},
	)

	s, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r, ok := s.Lookup("pypi", "pkg", "1.0.0")
	if !ok {
		t.Fatal("expected hit")
	}
	if r.MatchLevel != "version" {
		t.Errorf("MatchLevel = %q, want version", r.MatchLevel)
	}
}

// buildTestDB writes a bbolt file with pre-hashed entries and returns its path.
// versionEntries keys are "ecosystem:name:version", packageEntries keys are "ecosystem:name".
func buildTestDB(t *testing.T, versionEntries, packageEntries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.bolt")
	if err := store.Build(path, versionEntries, packageEntries, nil); err != nil {
		t.Fatalf("Build: %v", err)
	}
	return path
}

func TestLookupSemverRangeHit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.bolt")
	err := store.Build(path, nil, nil, []version.Range{
		{Ecosystem: "npm", Name: "evil-package", Introduced: "1.0.0", Fixed: "1.2.0", OSVID: "MAL-2024-002"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r, ok := s.Lookup("npm", "evil-package", "1.1.0")
	if !ok {
		t.Fatal("expected semver range hit for 1.1.0")
	}
	if r.OSVID != "MAL-2024-002" {
		t.Errorf("OSVID = %q, want MAL-2024-002", r.OSVID)
	}
	if r.MatchLevel != "version" {
		t.Errorf("MatchLevel = %q, want version", r.MatchLevel)
	}
}

func TestLookupSemverRangeMiss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.bolt")
	err := store.Build(path, nil, nil, []version.Range{
		{Ecosystem: "npm", Name: "evil-package", Introduced: "1.0.0", Fixed: "1.2.0", OSVID: "MAL-2024-002"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, ver := range []string{"0.9.9", "1.2.0", "2.0.0"} {
		_, ok := s.Lookup("npm", "evil-package", ver)
		if ok {
			t.Errorf("expected miss for %q, got hit", ver)
		}
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
