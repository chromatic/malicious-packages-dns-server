# malicious-packages DNS server

A DNS-based lookup service for the [ossf/malicious-packages](https://github.com/ossf/malicious-packages)
dataset. Clients query a DNS name derived from a package's ecosystem, name, and version; the server
responds with a DNSBL-style answer indicating whether the package is known-malicious.

---

## Repository layout

```
.
├── cmd/
│   ├── malicious-packages-dns/
│   │   └── main.go          # binary entrypoint: flags, signal handling, server lifecycle
│   └── ingest/
│       └── main.go          # CLI tool: walks OSV repo, writes malicious-packages.bolt
├── internal/
│   ├── store/
│   │   ├── store.go         # bbolt-backed store; Build(), Open(), Lookup(), LookupHash()
│   │   └── store_test.go
│   ├── ingest/
│   │   ├── ingest.go        # walks ossf repo tree, parses OSV JSON, calls store.Build()
│   │   └── ingest_test.go
│   ├── version/
│   │   ├── semver.go        # SEMVER range evaluation (blang/semver)
│   │   └── semver_test.go
│   └── dns/
│       └── handler.go       # miekg/dns handler; label decode, store lookup, response build
├── e2e/
│   └── e2e_test.go          # full-stack test: real UDP server, real bbolt db, dig-style queries
├── docker/
│   └── Dockerfile           # two-stage build with UPX compression; runtime FROM scratch
├── .github/
│   └── workflows/
│       ├── docker.yml        # build + push to ghcr.io/chromatic/malicious-packages-dns
│       └── rebuild-data.yml  # lives in chromatic/ossf-malicious-packages mirror repo
├── testdata/                 # small OSV JSON fixtures for unit tests
├── go.mod
├── go.sum
└── PLAN.md                  # this file
```

---

## DNS protocol design

### Label encoding

Version queries use **two labels** before the sublabel:

```
<verLabel>.<pkgLabel>.v.maliciouspackages.org.
```

- `verLabel` = `base32(plaintext_version_string)` — variable length, encodes the raw version
  string so the server can recover it and evaluate semver ranges
- `pkgLabel` = `base32(sha256("ecosystem:name")[:8])` — always 13 chars

Package queries use one label:

```
<pkgLabel>.p.maliciouspackages.org.
```

Base32 alphabet: `abcdefghijklmnopqrstuvwxyz234567` (RFC 4648 lowercase, no padding).
All fields normalised to lowercase before hashing.

The version string is encoded rather than hashed because semver range evaluation requires
the plaintext version at query time, and hashing is one-way.

`store.VersionLabel(ver)` and `store.PkgHashLabel(ecosystem, name)` are the canonical
client-side label construction functions.

### Response format

**Hit:** return `A 127.0.0.2` (DNSBL convention; do NOT use 127.0.0.1) plus a `TXT` record.

**Miss:** return `NXDOMAIN`.

**TXT record payload** (stay well under 255 bytes):

```
"osv=<OSV-ID> lvl=<version|package> reason=<malware|typosquat|…>"
```

If multiple OSV IDs apply, include the most recent one. The client can fetch full details from
the OSV API (`https://api.osv.dev/v1/vulns/<ID>`) if needed.

### SOA / TTL

| Record type     | TTL        | Notes                                      |
|-----------------|------------|--------------------------------------------|
| A / TXT (hit)   | 4 hours    | Positive: cached malicious result          |
| NXDOMAIN (miss) | 30 minutes | Shorter: new malicious packages propagate faster |
| SOA minimum     | 30 minutes | Controls negative caching per RFC 2308     |

---

## Data ingestion (`internal/ingest`)

### OSV field mapping

| OSV field                        | Usage                                    |
|----------------------------------|------------------------------------------|
| `affected[].package.ecosystem`   | Ecosystem (e.g. `PyPI`, `npm`, `Maven`)  |
| `affected[].package.name`        | Package name                             |
| `affected[].versions[]`          | Exact version strings → `.v.` entries    |
| `affected[].ranges[]`            | Range logic — see below                  |
| `id`                             | OSV ID stored in TXT record              |

### Version range decision tree

```
For each affected[] entry:
  1. If versions[] is non-empty:
       → index each version exactly in the version hash set
  2. Else examine ranges[]:
       a. Type == "SEMVER":
            → store the range bounds; evaluate at query time
            → (see version/semver.go)
       b. Type == "ECOSYSTEM":
            → block at package level (p. hash set); note in TXT
       c. Type == "GIT":
            → block at package level (p. hash set); note in TXT
       d. No ranges at all:
            → block at package level as a catch-all
```

The rationale: GIT ranges cannot be evaluated without the repo. ECOSYSTEM ranges require
per-ecosystem collation logic that is out of scope for v1. Blocking at package level is
conservative but correct — the TXT record tells the client why.

### SEMVER range evaluation

Use `github.com/blang/semver/v4`. Store ranges as `(ecosystem, name, introduced, fixed)` tuples
in a slice. At query time, walk the slice for the matching package and evaluate. This is O(n) over
ranges for that package — acceptable given dataset size.

```go
type SemverRange struct {
    Ecosystem  string
    Name       string
    Introduced semver.Version
    Fixed      semver.Version   // zero value means "no upper bound"
    OSVID      string
}
```

### Normalisation

Before hashing, normalise all fields:
- Ecosystem: lowercase (`pypi`, `npm`, `maven`, …)
- Name: lowercase; npm scoped packages keep the `@scope/name` form
- Version: use the raw string for exact matches; parse with blang/semver only for range evaluation

### Store structure

The store is a bbolt database with three buckets:

| Bucket | Key | Value |
|--------|-----|-------|
| `version` | `pkgHash(8) \|\| verHash(8)` (16 bytes) | OSV ID string |
| `package` | `pkgHash(8)` (8 bytes) | OSV ID string |
| `semver` | `pkgHash(8)` (8 bytes) | gob-encoded `[]rangeEntry{Introduced, Fixed, OSVID}` |

`pkgHash = sha256("ecosystem:name")[:8]`, `verHash = sha256(version)[:8]`.

`Build(path, versionEntries, packageEntries, ranges)` writes the database.
`Open(path) (*Store, error)` opens it read-only.
`Lookup(ecosystem, name, version string) (Result, bool)` is the high-level query entry point.
`LookupHash(verLabel, pkgLabel, bucket string) (Result, bool)` is called by the DNS handler.

---

## DNS handler (`internal/dns`)

Built on `github.com/miekg/dns`.

### Incoming label parsing

`.v.` queries: extract `verLabel` (first label), `pkgLabel` (second label), assert third label is `"v"`.
`.p.` queries: extract `pkgLabel` (first label, must be 13 chars), assert second label is `"p"`.

The handler calls `store.LookupHash(verLabel, pkgLabel, sublabel)`. For `.v.` queries the store
decodes `verLabel` back to the plaintext version string for semver range evaluation.

### Response construction

```go
// Hit
msg.Answer = append(msg.Answer,
    &dns.A{Hdr: hdr, A: net.ParseIP("127.0.0.2")},
    &dns.TXT{Hdr: hdr, Txt: []string{txtPayload}},
)

// Miss
msg.Rcode = dns.RcodeNameError   // NXDOMAIN
```

Set `msg.Authoritative = true`.

---

## Hot reload

The server watches for `SIGHUP`. On receipt:

1. Call `store.Open()` on the same `--data` path (updated bolt file should already be in place).
2. Atomically swap the pointer via `Handler.SwapStore`.
3. Close the old store.
4. Log the result.

No restart required. The caller (cron, systemd timer, etc.) is responsible for downloading the
new bolt file before sending SIGHUP.

---

## Client library (`pkg/client` — optional, add after server works)

```go
type Result struct {
    Blocked    bool
    MatchLevel string   // "version" | "package"
    OSVID      string
    Reason     string
}

// Check performs the two-step DNS lookup (v. then p.) concurrently.
func Check(ctx context.Context, resolver, ecosystem, pkg, version string) (Result, error)

// CheckAll performs concurrent lookups for a slice of packages.
// Parallelism is bounded internally (semaphore, default 20).
func CheckAll(ctx context.Context, resolver string, pkgs []PackageRef) ([]Result, error)
```

---

## Dockerfile

Two-stage build with UPX compression; final image is `FROM scratch`.

```dockerfile
# Stage 1: build and compress
FROM golang:latest AS builder
RUN apt-get update && apt-get install -y --no-install-recommends upx-ucl
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /malicious-packages-dns ./cmd/malicious-packages-dns
RUN upx --best --lzma /malicious-packages-dns

# Stage 2: runtime
FROM scratch
COPY --from=builder /malicious-packages-dns /malicious-packages-dns
EXPOSE 53/udp
EXPOSE 53/tcp
ENTRYPOINT ["/malicious-packages-dns", "--data=/data/malicious-packages.bolt"]
```

The bolt file is published **gzipped** (3.9MB) as a GitHub Release asset from `chromatic/ossf-malicious-packages`. bbolt requires it uncompressed on disk (36MB), so the download step must verify the signature and decompress before mounting:

```sh
BASE=https://github.com/chromatic/ossf-malicious-packages/releases/download/data-latest

curl -fsSL "$BASE/malicious-packages.bolt.gz.sha256" -o /tmp/malicious-packages.bolt.gz.sha256
curl -fsSL "$BASE/malicious-packages.bolt.gz" -o /tmp/malicious-packages.bolt.gz
sha256sum -c /tmp/malicious-packages.bolt.gz.sha256
gunzip -k /tmp/malicious-packages.bolt.gz
mv /tmp/malicious-packages.bolt /data/malicious-packages.bolt
```

```sh
docker run -d \
  -p 5353:53/udp \
  -p 5353:53/tcp \
  -v /data/malicious-packages.bolt:/data/malicious-packages.bolt:ro \
  ghcr.io/chromatic/malicious-packages-dns:latest
```

Use port 5353 locally to avoid needing root.

**Hot reload** — download new file alongside the live one, atomically replace, then SIGHUP:

```sh
gunzip -c /tmp/malicious-packages.bolt.gz > /data/malicious-packages.bolt.new
mv /data/malicious-packages.bolt.new /data/malicious-packages.bolt
kill -HUP $(cat /var/run/malicious-packages-dns.pid)
```

---

## GitHub Actions workflow (`.github/workflows/docker.yml`)

Trigger: push to `main` or a semver tag (`v*.*.*`).

Steps:
1. Checkout repo
2. `actions/setup-go` (match go.mod version)
3. Run tests: `go test ./...`
4. `docker/login-action` → `ghcr.io` using `GITHUB_TOKEN`
5. `docker/metadata-action` → generate tags (`latest`, git SHA, semver tag if present)
6. `docker/build-push-action` → build and push multi-arch (`linux/amd64`, `linux/arm64`)

Multi-arch matters because Hetzner's cheapest box (CAX11) is ARM64.

---

## Flags / configuration

| Flag          | Default                           | Description                            |
|---------------|-----------------------------------|----------------------------------------|
| `--data`      | `/data/malicious-packages.bolt`   | Path to bbolt data file                |
| `--listen`    | `:53`                             | UDP+TCP listen address                 |
| `--zone`      | `maliciouspackages.org.`          | Authoritative zone (trailing dot)      |
| `--ttl-hit`   | `14400` (4h)                      | TTL for positive responses             |
| `--ttl-miss`  | `1800` (30m)                      | TTL for NXDOMAIN / SOA minimum         |
| `--log-level` | `info`                            | `debug` / `info` / `warn` / `error`    |

---

## Implementation order

1. `internal/ingest` + `internal/store` with unit tests against a small fixture OSV file
2. `internal/version/semver.go` with range evaluation tests
3. `internal/dns/handler.go` wired to a stub store; verify responses with `dig`
4. `cmd/malicious-packages-dns/main.go`: flags, signal handling, hot reload
5. Dockerfile; verify `docker build` locally
6. GitHub Actions workflow

---

## Open questions / out of scope for v1

- Rate limiting (not needed for a private/team deployment; add if public)
- TCP fallback for large TXT responses (miekg/dns handles this automatically)
- Metrics endpoint (Prometheus `/metrics`) — worth adding in v2
- Per-ecosystem version collation for ECOSYSTEM ranges — punted to package-level block in v1
