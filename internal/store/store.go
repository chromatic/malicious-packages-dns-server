package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/gob"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/chromatic/malicious-packages-dns-server/internal/version"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketVersion = []byte("version") // key: pkgHash(8) || verHash(8), value: OSV ID
	bucketPackage = []byte("package") // key: pkgHash(8),               value: OSV ID
	bucketSemver  = []byte("semver")  // key: pkgHash(8),               value: gob([]rangeEntry)

	encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
)

// rangeEntry is the gob-serialisable form of a semver range stored in bbolt.
type rangeEntry struct {
	Introduced string
	Fixed      string // empty means no upper bound
	OSVID      string
}

// Result is returned by Lookup on a hit.
type Result struct {
	OSVID      string
	MatchLevel string // "version" or "package"
}

// Store is a read-only view of the bbolt database.
type Store struct {
	db         *bolt.DB
	rangeCache sync.Map // key: [8]byte (pkgHash), value: *version.RangeSet
}

// Open opens an existing bbolt database file for reading.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Lookup checks ecosystem+name+version against the store. Used by tests and the ingest tool.
func (s *Store) Lookup(ecosystem, name, ver string) (Result, bool) {
	pkgHash := pkgHashKey(ecosystem, name)
	verHash := verHashKey(ver)

	var result Result
	_ = s.db.View(func(tx *bolt.Tx) error {
		result = s.lookupVersion(tx, pkgHash, verHash, ver)
		if result.MatchLevel != "" {
			return nil
		}
		// Package-level fallback.
		if b := tx.Bucket(bucketPackage); b != nil {
			if v := b.Get(pkgHash); v != nil {
				result = Result{OSVID: string(v), MatchLevel: "package"}
			}
		}
		return nil
	})
	if result.MatchLevel == "" {
		return Result{}, false
	}
	return result, true
}

// LookupHash is called by the DNS handler with the two base32 labels from the query name.
// verLabel = base32(version string), pkgLabel = base32(sha256(ecosystem:name)[:8])
// bucket is "v" or "p".
func (s *Store) LookupHash(verLabel, pkgLabel, bucket string) (Result, bool) {
	// pkgLabel is always 13 chars → 8 bytes. Decode into a stack-allocated array.
	var pkgHash [8]byte
	n, err := encoding.Decode(pkgHash[:], []byte(pkgLabel))
	if err != nil || n != 8 {
		return Result{}, false
	}

	switch bucket {
	case "p":
		var result Result
		_ = s.db.View(func(tx *bolt.Tx) error {
			if b := tx.Bucket(bucketPackage); b != nil {
				if v := b.Get(pkgHash[:]); v != nil {
					result = Result{OSVID: string(v), MatchLevel: "package"}
				}
			}
			return nil
		})
		if result.MatchLevel == "" {
			return Result{}, false
		}
		return result, true

	case "v":
		// verLabel is base32(plaintext version string). The decoded bytes are always
		// treated as a string for semver parsing — never executed or passed to unsafe APIs.
		verBytes, err := encoding.DecodeString(verLabel)
		if err != nil {
			return Result{}, false
		}
		ver := string(verBytes)
		verHash := verHashKey(ver)

		var result Result
		_ = s.db.View(func(tx *bolt.Tx) error {
			result = s.lookupVersion(tx, pkgHash[:], verHash, ver)
			return nil
		})
		if result.MatchLevel == "" {
			return Result{}, false
		}
		return result, true

	default:
		return Result{}, false
	}
}

// lookupVersion is the shared transaction helper for exact-version + semver-range lookups.
// It does NOT check the package bucket; callers that need package-level fallback must do so separately.
func (s *Store) lookupVersion(tx *bolt.Tx, pkgHash, verHash []byte, ver string) Result {
	// Exact version hit. Use a stack-allocated [16]byte key to avoid a heap allocation per query.
	if b := tx.Bucket(bucketVersion); b != nil {
		var key [16]byte
		copy(key[:8], pkgHash)
		copy(key[8:], verHash)
		if v := b.Get(key[:]); v != nil {
			return Result{OSVID: string(v), MatchLevel: "version"}
		}
	}
	// Semver range fallback.
	if b := tx.Bucket(bucketSemver); b != nil {
		if v := b.Get(pkgHash); v != nil {
			if r, ok := s.evalRangesCached(pkgHash, v, ver); ok {
				return Result{OSVID: r.OSVID, MatchLevel: "version"}
			}
		}
	}
	return Result{}
}

// Build writes a new bbolt database at path.
// versionEntries keys: "ecosystem:name:version"; packageEntries keys: "ecosystem:name".
// ranges are stored in the semver bucket for query-time evaluation.
//
// The database is written to a temp file with FillPercent=1.0 (safe because it is
// written once and never updated), then compacted into path to reclaim freelist pages.
func Build(path string, versionEntries, packageEntries map[string]string, ranges []version.Range) error {
	// Write to a temp file alongside path so the final Compact rename is on the same filesystem.
	tmp := path + ".tmp"
	if err := buildInto(tmp, versionEntries, packageEntries, ranges); err != nil {
		os.Remove(tmp)
		return err
	}

	src, err := bolt.Open(tmp, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store.Build compact open src: %w", err)
	}
	dst, err := bolt.Open(path, 0600, nil)
	if err != nil {
		src.Close()
		os.Remove(tmp)
		return fmt.Errorf("store.Build compact open dst: %w", err)
	}
	if err := bolt.Compact(dst, src, 0); err != nil {
		dst.Close()
		src.Close()
		os.Remove(tmp)
		return fmt.Errorf("store.Build compact: %w", err)
	}
	dst.Close()
	src.Close()
	os.Remove(tmp)
	return nil
}

func buildInto(path string, versionEntries, packageEntries map[string]string, ranges []version.Range) error {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return fmt.Errorf("store.Build: %w", err)
	}
	defer db.Close()

	return db.Update(func(tx *bolt.Tx) error {
		vb, err := tx.CreateBucketIfNotExists(bucketVersion)
		if err != nil {
			return err
		}
		pb, err := tx.CreateBucketIfNotExists(bucketPackage)
		if err != nil {
			return err
		}
		sb, err := tx.CreateBucketIfNotExists(bucketSemver)
		if err != nil {
			return err
		}

		// The database is written once and never updated, so pages can be packed
		// tightly. FillPercent=1.0 tells bbolt not to reserve space for future splits.
		vb.FillPercent = 1.0
		pb.FillPercent = 1.0
		sb.FillPercent = 1.0

		for k, osvID := range versionEntries {
			// k = "ecosystem:name:version"
			parts := strings.SplitN(k, ":", 3)
			if len(parts) != 3 {
				continue
			}
			key := append(pkgHashKey(parts[0], parts[1]), verHashKey(parts[2])...)
			if err := vb.Put(key, []byte(osvID)); err != nil {
				return err
			}
		}
		for k, osvID := range packageEntries {
			// k = "ecosystem:name"
			parts := strings.SplitN(k, ":", 2)
			if len(parts) != 2 {
				continue
			}
			if err := pb.Put(pkgHashKey(parts[0], parts[1]), []byte(osvID)); err != nil {
				return err
			}
		}

		// Group ranges by pkgHash and gob-encode each group.
		byPkg := make(map[string][]rangeEntry)
		for _, r := range ranges {
			key := string(pkgHashKey(r.Ecosystem, r.Name))
			byPkg[key] = append(byPkg[key], rangeEntry{
				Introduced: r.Introduced,
				Fixed:      r.Fixed,
				OSVID:      r.OSVID,
			})
		}
		for pkgKey, entries := range byPkg {
			var buf bytes.Buffer
			if err := gob.NewEncoder(&buf).Encode(entries); err != nil {
				return err
			}
			if err := sb.Put([]byte(pkgKey), buf.Bytes()); err != nil {
				return err
			}
		}
		return nil
	})
}

// VersionLabel returns the base32 encoding of the plaintext version string.
// This is what the client puts in the first label of a .v. query.
func VersionLabel(ver string) string {
	return encoding.EncodeToString([]byte(ver))
}

// PkgHashLabel returns the 13-char base32 label for ecosystem+name.
// This is what the client puts in the second label of a .v. query, and the only label of a .p. query.
func PkgHashLabel(ecosystem, name string) string {
	return encoding.EncodeToString(pkgHashKey(ecosystem, name))
}

// pkgHashKey returns the 8-byte truncated SHA-256 of "ecosystem:name" (lowercased).
func pkgHashKey(ecosystem, name string) []byte {
	return truncHash(strings.ToLower(ecosystem) + ":" + strings.ToLower(name))
}

// verHashKey returns the 8-byte truncated SHA-256 of version.
func verHashKey(ver string) []byte {
	return truncHash(ver)
}

func truncHash(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	// 8 bytes (64-bit key). Birthday-paradox collision probability reaches ~50% at ~4.3 billion
	// entries; the ossf/malicious-packages dataset is currently ~250k entries, well below that bound.
	return sum[:8]
}

// evalRangesCached decodes a gob-encoded []rangeEntry (caching the parsed RangeSet) and
// returns the first matching range for ver. The store is read-only after Open, so the
// cache is safe to populate lazily and never needs invalidation.
//
// The cache key is [8]byte (not string) to avoid a heap allocation on every lookup.
func (s *Store) evalRangesCached(pkgHash []byte, data []byte, ver string) (rangeEntry, bool) {
	var key [8]byte
	copy(key[:], pkgHash)

	if cached, ok := s.rangeCache.Load(key); ok {
		r, ok := cached.(*version.RangeSet).LookupVersion(ver)
		if !ok {
			return rangeEntry{}, false
		}
		return rangeEntry{OSVID: r.OSVID}, true
	}

	var entries []rangeEntry
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entries); err != nil {
		return rangeEntry{}, false
	}
	rs := version.NewRangeSet()
	for _, e := range entries {
		rs.Add(version.Range{
			Introduced: e.Introduced,
			Fixed:      e.Fixed,
			OSVID:      e.OSVID,
		})
	}
	s.rangeCache.Store(key, rs)

	r, ok := rs.LookupVersion(ver)
	if !ok {
		return rangeEntry{}, false
	}
	return rangeEntry{OSVID: r.OSVID}, true
}
