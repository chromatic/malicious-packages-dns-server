package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"strings"

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
	db *bolt.DB
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
		if b := tx.Bucket(bucketVersion); b != nil {
			if v := b.Get(append(pkgHash, verHash...)); v != nil {
				result = Result{OSVID: string(v), MatchLevel: "version"}
				return nil
			}
		}
		// Semver ranges
		if b := tx.Bucket(bucketSemver); b != nil {
			if v := b.Get(pkgHash); v != nil {
				if r, ok := evalRanges(v, ver); ok {
					result = Result{OSVID: r.OSVID, MatchLevel: "version"}
					return nil
				}
			}
		}
		if b := tx.Bucket(bucketPackage); b != nil {
			if v := b.Get(pkgHash); v != nil {
				result = Result{OSVID: string(v), MatchLevel: "package"}
				return nil
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
	switch bucket {
	case "p":
		pkgHash, err := encoding.DecodeString(pkgLabel)
		if err != nil {
			return Result{}, false
		}
		var result Result
		_ = s.db.View(func(tx *bolt.Tx) error {
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

	case "v":
		pkgHash, err := encoding.DecodeString(pkgLabel)
		if err != nil {
			return Result{}, false
		}
		// Decode verLabel back to the plaintext version string.
		verBytes, err := encoding.DecodeString(verLabel)
		if err != nil {
			return Result{}, false
		}
		ver := string(verBytes)
		verHash := verHashKey(ver)

		var result Result
		_ = s.db.View(func(tx *bolt.Tx) error {
			// Exact version hit.
			if b := tx.Bucket(bucketVersion); b != nil {
				if v := b.Get(append(pkgHash, verHash...)); v != nil {
					result = Result{OSVID: string(v), MatchLevel: "version"}
					return nil
				}
			}
			// Semver range fallback.
			if b := tx.Bucket(bucketSemver); b != nil {
				if v := b.Get(pkgHash); v != nil {
					if r, ok := evalRanges(v, ver); ok {
						result = Result{OSVID: r.OSVID, MatchLevel: "version"}
					}
				}
			}
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

// Build writes a new bbolt database at path.
// versionEntries keys: "ecosystem:name:version"; packageEntries keys: "ecosystem:name".
// ranges are stored in the semver bucket for query-time evaluation.
func Build(path string, versionEntries, packageEntries map[string]string, ranges []version.Range) error {
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
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, binary.BigEndian.Uint64(sum[:8]))
	return key
}

// evalRanges decodes a gob-encoded []rangeEntry and returns the first matching range for ver.
func evalRanges(data []byte, ver string) (rangeEntry, bool) {
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
	r, ok := rs.LookupVersion(ver)
	if !ok {
		return rangeEntry{}, false
	}
	return rangeEntry{OSVID: r.OSVID}, true
}
