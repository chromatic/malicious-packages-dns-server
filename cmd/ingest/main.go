package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/chromatic/malicious-packages-dns-server/internal/ingest"
)

func main() {
	repo := flag.String("repo", ".", "Path to ossf/malicious-packages checkout")
	out  := flag.String("out", "malicious-packages.bolt", "Output bbolt file path")
	flag.Parse()

	slog.Info("ingesting", "repo", *repo, "out", *out)
	if err := ingest.Build(*repo, *out); err != nil {
		slog.Error("ingest failed", "err", err)
		os.Exit(1)
	}
	slog.Info("done")
}
