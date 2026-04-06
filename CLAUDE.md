# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A DNS-based lookup service for the [ossf/malicious-packages](https://github.com/ossf/malicious-packages) dataset. Clients query a DNS name derived from a package's ecosystem, name, and version; the server responds with a DNSBL-style answer indicating whether the package is known-malicious.

## Commands

```sh
# Build all
go build ./...

# Run all tests (unit + e2e)
go test ./...

# Run a single package's tests
go test ./internal/store/...
go test ./internal/ingest/...
go test ./internal/version/...
go test ./e2e/...

# Build the server binary
go build -o malicious-packages-dns ./cmd/malicious-packages-dns

# Build the ingest binary (produces the bbolt data file)
go build -o ingest ./cmd/ingest

# Run ingest against a local ossf repo checkout
./ingest --repo=/path/to/ossf-malicious-packages --out=malicious-packages.bolt

# Run the server
./malicious-packages-dns --data=/path/to/malicious-packages.bolt

# Build Docker image (Dockerfile is in docker/ subdirectory)
docker build -f docker/Dockerfile -t malicious-packages-dns .

# Reload data file without restart
kill -HUP <pid>
```

## Architecture

### Data flow

```
ossf/malicious-packages (OSV JSON files)
  → cmd/ingest        builds malicious-packages.bolt
  → server mounts it  at startup and on SIGHUP
  → DNS clients       query the server
```

The bolt file is published as a GitHub Release asset from `chromatic/ossf-malicious-packages` on every push to main (see `.github/workflows/rebuild-data.yml`, which lives in that repo).

### DNS protocol

Two query forms:

```
# Version query (exact match or semver range)
<base32(version)>.<base32(sha256(ecosystem:name)[:8])>.v.maliciouspackages.org.

# Package query (any version)
<base32(sha256(ecosystem:name)[:8])>.p.maliciouspackages.org.
```

- Version label: `base32(plaintext_version_string)` — variable length, no padding
- Package label: `base32(sha256("ecosystem:name")[:8])` — always 13 chars
- Base32 alphabet: `abcdefghijklmnopqrstuvwxyz234567` (RFC 4648 lowercase, no padding)
- All fields normalised to lowercase before hashing

Responses: hit = `A 127.0.0.2` + TXT (never 127.0.0.1); miss = NXDOMAIN.
TXT format: `"osv=<ID> lvl=<version|package>"`. TTLs: hits 4h, misses/SOA 30m.

`store.VersionLabel(ver)` and `store.PkgHashLabel(ecosystem, name)` are the canonical label-construction functions used by both tests and any future client code.

### Store (`internal/store`)

bbolt database with three buckets:

| Bucket | Key | Value |
|--------|-----|-------|
| `version` | `pkgHash(8) \|\| verHash(8)` | OSV ID string |
| `package` | `pkgHash(8)` | OSV ID string |
| `semver` | `pkgHash(8)` | gob-encoded `[]rangeEntry{Introduced, Fixed, OSVID}` |

`LookupHash(verLabel, pkgLabel, bucket)` is called by the DNS handler. For `.v.` queries it checks the version bucket first, then evaluates semver ranges on a miss. The version string is recovered by base32-decoding `verLabel`.

`Build(path, versionEntries, packageEntries, ranges)` is used by both ingest and tests.

### Ingest (`internal/ingest`)

Walks OSV JSON files. Version indexing decision tree:
1. `affected[].versions[]` non-empty → exact entries in version bucket
2. Else inspect `ranges[]`:
   - `SEMVER` → parse introduced/fixed, store in semver bucket
   - `ECOSYSTEM`, `GIT`, or no ranges → package-level block

### Version (`internal/version`)

`RangeSet.Lookup(ecosystem, name, ver)` — filters by package then evaluates semver bounds.
`RangeSet.LookupVersion(ver)` — evaluates bounds only, used when the set is already narrowed to one package by the bbolt key.

### DNS handler (`internal/dns`)

`parseLabels` handles both query forms. `.v.` expects 3 parts before the zone (`verLabel.pkgLabel.v`); `.p.` expects 2 parts (`pkgLabel.p`). Store is swapped atomically via `Handler.SwapStore` on SIGHUP.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--data` | `/data/malicious-packages.bolt` | Path to bbolt data file |
| `--listen` | `:53` | UDP+TCP listen address |
| `--zone` | `maliciouspackages.org.` | Authoritative zone (trailing dot) |
| `--ttl-hit` | `14400` | TTL for positive responses (seconds) |
| `--ttl-miss` | `1800` | TTL for NXDOMAIN / SOA minimum (seconds) |
| `--log-level` | `info` | `debug` / `info` / `warn` / `error` |

### Deployment

The bolt file is stored gzipped (3.9MB) in the GitHub Release and must be decompressed before mounting. bbolt memory-maps the file directly and requires it uncompressed on disk (36MB).

**Initial download:**

```sh
BASE=https://github.com/chromatic/ossf-malicious-packages/releases/download/data-latest

curl -fsSL "$BASE/malicious-packages.bolt.gz.sha256" -o /tmp/malicious-packages.bolt.gz.sha256
curl -fsSL "$BASE/malicious-packages.bolt.gz" -o /tmp/malicious-packages.bolt.gz
sha256sum -c /tmp/malicious-packages.bolt.gz.sha256
gunzip -k /tmp/malicious-packages.bolt.gz   # produces malicious-packages.bolt
mv /tmp/malicious-packages.bolt /data/malicious-packages.bolt
```

**Run the container:**

```sh
docker run -d \
  -p 5353:53/udp \
  -p 5353:53/tcp \
  -v /data/malicious-packages.bolt:/data/malicious-packages.bolt:ro \
  ghcr.io/chromatic/malicious-packages-dns:latest
```

Use port 5353 locally to avoid needing root. Multi-arch build (`linux/amd64`, `linux/arm64`) for Hetzner CAX11.

**Hot reload (atomic update):**

```sh
BASE=https://github.com/chromatic/ossf-malicious-packages/releases/download/data-latest

curl -fsSL "$BASE/malicious-packages.bolt.gz.sha256" -o /tmp/malicious-packages.bolt.gz.sha256
curl -fsSL "$BASE/malicious-packages.bolt.gz" -o /tmp/malicious-packages.bolt.gz
sha256sum -c /tmp/malicious-packages.bolt.gz.sha256
gunzip -c /tmp/malicious-packages.bolt.gz > /data/malicious-packages.bolt.new
mv /data/malicious-packages.bolt.new /data/malicious-packages.bolt  # atomic on same fs
kill -HUP $(cat /var/run/malicious-packages-dns.pid)
```

`mv` is atomic on the same filesystem so the server never sees a partial file. The SIGHUP causes the server to call `store.Open()` on the same `--data` path and swap the pointer without restarting.
