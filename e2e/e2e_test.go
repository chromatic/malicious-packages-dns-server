package e2e_test

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internaldns "github.com/chromatic/malicious-packages-dns-server/internal/dns"
	"github.com/chromatic/malicious-packages-dns-server/internal/store"
	"github.com/chromatic/malicious-packages-dns-server/internal/version"
	miekgdns "github.com/miekg/dns"
)

const testZone = "maliciouspackages.org."

// testServer starts a real UDP DNS server on a random port and returns the address.
func testServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "e2e.bolt")
	err := store.Build(dbPath,
		// Exact version entries
		map[string]string{
			"pypi:malicious-pkg:1.0.0": "MAL-2024-001",
			"pypi:malicious-pkg:1.0.1": "MAL-2024-001",
		},
		// Package-level entries (any version)
		map[string]string{
			"npm:@scope/scoped-evil": "MAL-2024-003",
		},
		// Semver range entries: npm/evil-package [1.0.0, 1.2.0)
		[]version.Range{
			{
				Ecosystem:  "npm",
				Name:       "evil-package",
				Introduced: "1.0.0",
				Fixed:      "1.2.0",
				OSVID:      "MAL-2024-002",
			},
		},
	)
	if err != nil {
		t.Fatalf("store.Build: %v", err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	handler := internaldns.NewHandler(s, testZone, 14400, 1800)

	srv := &miekgdns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "udp",
		Handler: handler,
	}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// Server closed — normal during test teardown.
		}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server did not start in time")
	}

	return srv.PacketConn.LocalAddr().String(), func() {
		srv.Shutdown()
		s.Close()
	}
}

// ask issues a DNS A query and returns the response message.
func ask(t *testing.T, addr, qname string) *miekgdns.Msg {
	t.Helper()
	c := new(miekgdns.Client)
	c.Net = "udp"
	m := new(miekgdns.Msg)
	m.SetQuestion(miekgdns.Fqdn(qname), miekgdns.TypeA)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS exchange for %q: %v", qname, err)
	}
	return resp
}

func vName(ecosystem, name, ver string) string {
	return store.VersionLabel(ver) + "." + store.PkgHashLabel(ecosystem, name) + ".v." + testZone
}

func pName(ecosystem, name string) string {
	return store.PkgHashLabel(ecosystem, name) + ".p." + testZone
}

func assertHit(t *testing.T, msg *miekgdns.Msg, wantOSVID, wantLevel string) {
	t.Helper()
	if msg.Rcode != miekgdns.RcodeSuccess {
		t.Fatalf("rcode = %d (%s), want NOERROR", msg.Rcode, miekgdns.RcodeToString[msg.Rcode])
	}
	if !msg.Authoritative {
		t.Error("expected Authoritative = true")
	}
	var gotA, gotTXT bool
	for _, rr := range msg.Answer {
		switch r := rr.(type) {
		case *miekgdns.A:
			gotA = true
			if !r.A.Equal(net.ParseIP("127.0.0.2")) {
				t.Errorf("A record = %v, want 127.0.0.2", r.A)
			}
		case *miekgdns.TXT:
			gotTXT = true
			txt := strings.Join(r.Txt, "")
			if !strings.Contains(txt, wantOSVID) {
				t.Errorf("TXT %q: missing OSV ID %q", txt, wantOSVID)
			}
			if !strings.Contains(txt, "lvl="+wantLevel) {
				t.Errorf("TXT %q: missing lvl=%s", txt, wantLevel)
			}
		}
	}
	if !gotA {
		t.Error("missing A record in answer")
	}
	if !gotTXT {
		t.Error("missing TXT record in answer")
	}
}

func assertNXDOMAIN(t *testing.T, msg *miekgdns.Msg) {
	t.Helper()
	if msg.Rcode != miekgdns.RcodeNameError {
		t.Errorf("rcode = %d (%s), want NXDOMAIN", msg.Rcode, miekgdns.RcodeToString[msg.Rcode])
	}
}

// --- Tests ---

func TestE2E_ExactVersionHit(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	msg := ask(t, addr, vName("pypi", "malicious-pkg", "1.0.0"))
	assertHit(t, msg, "MAL-2024-001", "version")
}

func TestE2E_ExactVersionHitSecondVersion(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	msg := ask(t, addr, vName("pypi", "malicious-pkg", "1.0.1"))
	assertHit(t, msg, "MAL-2024-001", "version")
}

func TestE2E_ExactVersionMissWrongVersion(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	msg := ask(t, addr, vName("pypi", "malicious-pkg", "2.0.0"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_ExactVersionMissUnknownPackage(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	msg := ask(t, addr, vName("pypi", "clean-pkg", "1.0.0"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_PackageLevelHit(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	msg := ask(t, addr, pName("npm", "@scope/scoped-evil"))
	assertHit(t, msg, "MAL-2024-003", "package")
}

func TestE2E_PackageLevelMissUnknownPackage(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	msg := ask(t, addr, pName("npm", "clean-package"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_SemverInRange(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// 1.1.0 is in [1.0.0, 1.2.0)
	msg := ask(t, addr, vName("npm", "evil-package", "1.1.0"))
	assertHit(t, msg, "MAL-2024-002", "version")
}

func TestE2E_SemverAtIntroducedBoundary(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// 1.0.0 is the introduced version — should be a hit
	msg := ask(t, addr, vName("npm", "evil-package", "1.0.0"))
	assertHit(t, msg, "MAL-2024-002", "version")
}

func TestE2E_SemverBelowRange(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// 0.9.9 is before introduced — miss
	msg := ask(t, addr, vName("npm", "evil-package", "0.9.9"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_SemverAtFixedBoundary(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// 1.2.0 is the fixed version — excluded, should be miss
	msg := ask(t, addr, vName("npm", "evil-package", "1.2.0"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_SemverAboveRange(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// 2.0.0 is above fixed — miss
	msg := ask(t, addr, vName("npm", "evil-package", "2.0.0"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_VersionHitDoesNotRespondOnPackageSublabel(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// pypi:malicious-pkg is only in the version bucket, not the package bucket
	msg := ask(t, addr, pName("pypi", "malicious-pkg"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_PackageHitDoesNotRespondOnVersionSublabel(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// npm:@scope/scoped-evil is only in the package bucket
	msg := ask(t, addr, vName("npm", "@scope/scoped-evil", "1.0.0"))
	assertNXDOMAIN(t, msg)
}

func TestE2E_MalformedLabelNXDOMAIN(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	// Label that doesn't match our format at all
	msg := ask(t, addr, "notourlabel.v."+testZone)
	assertNXDOMAIN(t, msg)
}

func TestE2E_WrongZoneNXDOMAIN(t *testing.T) {
	addr, cleanup := testServer(t)
	t.Cleanup(cleanup)

	msg := ask(t, addr, vName("pypi", "malicious-pkg", "1.0.0")[:len(vName("pypi", "malicious-pkg", "1.0.0"))-len(testZone)]+"example.com.")
	assertNXDOMAIN(t, msg)
}
