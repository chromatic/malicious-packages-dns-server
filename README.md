# malicious-packages-dns-server

A DNS-based lookup service for the [ossf/malicious-packages](https://github.com/ossf/malicious-packages) dataset. Query a package by ecosystem, name, and version; get back a DNSBL-style response telling you whether it is known-malicious.

## How it works

The server answers DNS queries of the form:

```
<base32(version)>.<base32(sha256(ecosystem:name)[:8])>.v.maliciouspackages.org.
```

- **Hit** (malicious): returns `A 127.0.0.2` + a TXT record: `osv=MAL-2024-001 lvl=version`
- **Miss** (clean): returns `NXDOMAIN`

Package-level blocks (where all versions of a package are malicious) are served from the `.p.` sublabel and are checked automatically by the query script.

The data is rebuilt every 3 hours from [ossf/malicious-packages](https://github.com/ossf/malicious-packages) and published as a release asset here.

## Quick start

**1. Get the data file**

```sh
BASE=https://github.com/chromatic/malicious-packages-dns-server/releases/download/data-latest
DATADIR=/var/lib/malicious-packages-dns
mkdir -p "$DATADIR"

curl -fsSL "$BASE/malicious-packages.bolt.gz.sha256" -o "$DATADIR/malicious-packages.bolt.gz.sha256"
curl -fsSL "$BASE/malicious-packages.bolt.gz"        -o "$DATADIR/malicious-packages.bolt.gz"

# Verify — sha256sum -c expects the file named in the .sha256 to exist in the same directory
(cd "$DATADIR" && sha256sum -c malicious-packages.bolt.gz.sha256) || { echo "checksum failed"; exit 1; }

gunzip "$DATADIR/malicious-packages.bolt.gz"
```

**2. Run the server**

```sh
docker run -d \
  --name malicious-packages-dns \
  -p 5353:53/udp \
  -p 5353:53/tcp \
  -v "$DATADIR/malicious-packages.bolt":/data/malicious-packages.bolt:ro \
  ghcr.io/chromatic/malicious-packages-dns-server:main
```

Use port 5353 to avoid needing root. Change to `-p 53:53` if you want the standard DNS port.

**3. Query it**

```sh
./query.sh <ecosystem> <package> <version> [server:port]
```

Examples:

```sh
./query.sh pypi litellm 1.82.7 127.0.0.1:5353
# MALICIOUS (version match)
# "osv=MAL-2026-2144 lvl=version"

./query.sh npm axios 0.30.4 127.0.0.1:5353
# MALICIOUS (version match)
# "osv=MAL-2026-2307 lvl=version"

./query.sh pypi litellm 1.84.0 127.0.0.1:5353
# CLEAN

./query.sh npm axios 1.13.5 127.0.0.1:5353
# CLEAN
```

`query.sh` exits `0` for clean packages and `1` for malicious ones, so it can be used in scripts.

## Keeping the data up to date

The data file is rebuilt automatically every 3 hours if new commits appear in ossf/malicious-packages. To update your local copy and hot-reload the server without restarting:

```sh
BASE=https://github.com/chromatic/malicious-packages-dns-server/releases/download/data-latest
DATADIR=/var/lib/malicious-packages-dns

curl -fsSL "$BASE/malicious-packages.bolt.gz.sha256" -o "$DATADIR/new.bolt.gz.sha256"
curl -fsSL "$BASE/malicious-packages.bolt.gz"        -o "$DATADIR/new.bolt.gz"

# Verify before replacing
(cd "$DATADIR" && sha256sum -c new.bolt.gz.sha256) || { echo "checksum failed, aborting reload"; exit 1; }

gunzip -c "$DATADIR/new.bolt.gz" > "$DATADIR/malicious-packages.bolt.new"
mv "$DATADIR/malicious-packages.bolt.new" "$DATADIR/malicious-packages.bolt"
docker kill --signal HUP malicious-packages-dns
```

## Building from source

Requires Go 1.22+.

```sh
git clone https://github.com/chromatic/malicious-packages-dns-server
cd malicious-packages-dns-server

# Build the server
go build -o malicious-packages-dns ./cmd/malicious-packages-dns

# Build the ingest tool (to build your own data file)
go build -o ingest ./cmd/ingest

# Run tests
go test ./...

# Build your own data file from a local ossf/malicious-packages checkout
./ingest --repo=/path/to/ossf-malicious-packages --out=malicious-packages.bolt

# Run the server
./malicious-packages-dns --data=malicious-packages.bolt --listen=:5353
```

## Data file sizes

| File | Size |
|------|------|
| `malicious-packages.bolt.gz` (download) | ~4 MB |
| `malicious-packages.bolt` (on disk) | ~36 MB |
| Docker image | ~1.9 MB |

## Response format

| Field | Values |
|-------|--------|
| A record | `127.0.0.2` on a hit (never `127.0.0.1`) |
| TXT `osv=` | OSV ID, e.g. `MAL-2024-001` |
| TXT `lvl=` | `version` (exact or semver match) or `package` (all versions blocked) |
| TTL on hit | 4 hours |
| TTL on miss | 30 minutes |

Full OSV details for any ID are available at `https://api.osv.dev/v1/vulns/<ID>`.

## License

Apache 2.0. The underlying data is from [ossf/malicious-packages](https://github.com/ossf/malicious-packages) and is subject to its own license.
