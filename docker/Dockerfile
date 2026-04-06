# Stage 1: build and compress
FROM golang:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends upx-ucl && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /malicious-packages-dns ./cmd/malicious-packages-dns
RUN upx --best --lzma /malicious-packages-dns

# Stage 2: minimal runtime
FROM scratch
COPY --from=builder /malicious-packages-dns /malicious-packages-dns
# bbolt data file must be mounted at /data/malicious-packages.bolt at runtime
EXPOSE 53/udp
EXPOSE 53/tcp
ENTRYPOINT ["/malicious-packages-dns", "--data=/data/malicious-packages.bolt"]
