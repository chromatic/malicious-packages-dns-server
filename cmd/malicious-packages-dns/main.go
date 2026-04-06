package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	internaldns "github.com/chromatic/malicious-packages-dns/internal/dns"
	"github.com/chromatic/malicious-packages-dns/internal/store"
	miekgdns "github.com/miekg/dns"
)

func main() {
	dataFile  := flag.String("data", "/data/malicious-packages.bolt", "Path to bbolt data file")
	listen    := flag.String("listen", ":53", "UDP+TCP listen address")
	zone      := flag.String("zone", "maliciouspackages.org.", "Authoritative zone (trailing dot)")
	ttlHit    := flag.Uint("ttl-hit", 14400, "TTL for positive responses (seconds)")
	ttlMiss   := flag.Uint("ttl-miss", 1800, "TTL for NXDOMAIN responses (seconds)")
	logLevel  := flag.String("log-level", "info", "Log level: debug|info|warn|error")
	flag.Parse()

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	s, err := store.Open(*dataFile)
	if err != nil {
		slog.Error("failed to open data file", "err", err)
		os.Exit(1)
	}

	handler := internaldns.NewHandler(s, *zone, uint32(*ttlHit), uint32(*ttlMiss))

	udpServer := &miekgdns.Server{Addr: *listen, Net: "udp", Handler: handler}
	tcpServer := &miekgdns.Server{Addr: *listen, Net: "tcp", Handler: handler}

	errc := make(chan error, 2)
	go func() { errc <- udpServer.ListenAndServe() }()
	go func() { errc <- tcpServer.ListenAndServe() }()
	slog.Info("listening", "addr", *listen, "zone", *zone)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case err := <-errc:
			slog.Error("server error", "err", err)
			os.Exit(1)

		case sig := <-sigc:
			switch sig {
			case syscall.SIGHUP:
				slog.Info("SIGHUP received, reloading data file")
				newStore, err := store.Open(*dataFile)
				if err != nil {
					slog.Error("reload failed, keeping old data", "err", err)
					continue
				}
				old := handler.SwapStore(newStore)
				old.Close()
				slog.Info("data file reloaded")

			default:
				slog.Info("shutting down", "signal", sig)
				udpServer.Shutdown()
				tcpServer.Shutdown()
				s.Close()
				return
			}
		}
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
