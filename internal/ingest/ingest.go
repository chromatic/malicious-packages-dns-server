package ingest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
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

		// Guard against symlinks escaping the repo directory.
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("evalSymlinks %s: %w", path, err)
		}
		absResolved, err := filepath.Abs(resolved)
		if err != nil {
			return fmt.Errorf("abs resolved path: %w", err)
		}
		absRepo, err := filepath.Abs(repoPath)
		if err != nil {
			return fmt.Errorf("abs repoPath: %w", err)
		}
		if !strings.HasPrefix(absResolved, absRepo+string(filepath.Separator)) && absResolved != absRepo {
			slog.Warn("skipping symlink outside repo", "path", path, "resolved", absResolved)
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var rec osvRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			slog.Warn("skipping malformed OSV file", "path", path, "err", err)
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
				// OSV SEMVER ranges can contain multiple (introduced, fixed) event pairs.
				// Emit one version.Range per pair so all affected spans are captured.
				var currentIntroduced string
				for _, e := range r.Events {
					if e.Introduced != "" {
						currentIntroduced = e.Introduced
					}
					if e.Fixed != "" && currentIntroduced != "" {
						semverRanges = append(semverRanges, version.Range{
							Ecosystem:  eco,
							Name:       name,
							Introduced: currentIntroduced,
							Fixed:      e.Fixed,
							OSVID:      rec.ID,
						})
						currentIntroduced = ""
					}
				}
				// Trailing open-ended range (introduced with no following fixed).
				if currentIntroduced != "" && currentIntroduced != "0" {
					semverRanges = append(semverRanges, version.Range{
						Ecosystem:  eco,
						Name:       name,
						Introduced: currentIntroduced,
						OSVID:      rec.ID,
					})
				}
				// SEMVER with only introduced="0" and no fixed means all versions
				// are affected — treat as a package-level block.
				if currentIntroduced == "0" {
					packageEntries[pkgKey] = rec.ID
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
