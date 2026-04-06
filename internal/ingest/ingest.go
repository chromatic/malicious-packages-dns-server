package ingest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/chromatic/malicious-packages-dns-server/internal/store"
	"github.com/chromatic/malicious-packages-dns-server/internal/version"
)

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []osvRange `json:"ranges"`
}

type osvRecord struct {
	ID       string        `json:"id"`
	Affected []osvAffected `json:"affected"`
}

// Build walks repoPath for OSV JSON files, computes hashes, and writes a
// bbolt database to outPath.
func Build(repoPath, outPath string) error {
	versionEntries := make(map[string]string)
	packageEntries := make(map[string]string)
	var semverRanges []version.Range

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var rec osvRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil // skip malformed files
		}

		for _, affected := range rec.Affected {
			eco := strings.ToLower(affected.Package.Ecosystem)
			name := strings.ToLower(affected.Package.Name)

			if len(affected.Versions) > 0 {
				for _, v := range affected.Versions {
					versionEntries[eco+":"+name+":"+v] = rec.ID
				}
				continue
			}

			// No exact versions — inspect ranges.
			pkgKey := eco + ":" + name
			for _, r := range affected.Ranges {
				if r.Type != "SEMVER" {
					// ECOSYSTEM, GIT ranges → package-level block.
					packageEntries[pkgKey] = rec.ID
					continue
				}
				var introduced, fixed string
				for _, e := range r.Events {
					if e.Introduced != "" {
						introduced = e.Introduced
					}
					if e.Fixed != "" {
						fixed = e.Fixed
					}
				}
				// SEMVER with introduced="0" and no fixed means all versions
				// are affected — treat as a package-level block rather than
				// storing a vacuous range entry.
				if (introduced == "0" || introduced == "") && fixed == "" {
					packageEntries[pkgKey] = rec.ID
					continue
				}
				if introduced != "" {
					semverRanges = append(semverRanges, version.Range{
						Ecosystem:  eco,
						Name:       name,
						Introduced: introduced,
						Fixed:      fixed,
						OSVID:      rec.ID,
					})
				}
			}
			// No ranges at all → package-level block.
			if len(affected.Ranges) == 0 {
				packageEntries[pkgKey] = rec.ID
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("ingest.Build walk: %w", err)
	}

	return store.Build(outPath, versionEntries, packageEntries, semverRanges)
}
