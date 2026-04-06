package dns_test

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chromatic/malicious-packages-dns/internal/dns"
	"github.com/chromatic/malicious-packages-dns/internal/store"
	miekgdns "github.com/miekg/dns"
)

const zone = "maliciouspackages.org."

func newHandler(t *testing.T) *dns.Handler {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.bolt")
	err := store.Build(dbPath,
		map[string]string{
			"pypi:malicious-pkg:1.0.0": "MAL-2024-001",
		},
		map[string]string{
			"npm:@scope/scoped-evil": "MAL-2024-003",
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return dns.NewHandler(s, zone, 14400, 1800)
}

func vQuery(ecosystem, name, version, zone string) string {
	return store.VersionLabel(version) + "." + store.PkgHashLabel(ecosystem, name) + ".v." + zone
}

func pQuery(ecosystem, name, zone string) string {
	return store.PkgHashLabel(ecosystem, name) + ".p." + zone
}

func query(t *testing.T, h *dns.Handler, qname string, qtype uint16) *miekgdns.Msg {
	t.Helper()
	req := new(miekgdns.Msg)
	req.SetQuestion(miekgdns.Fqdn(qname), qtype)
	w := &testResponseWriter{}
	h.ServeDNS(w, req)
	if w.msg == nil {
		t.Fatal("handler did not write a response")
	}
	return w.msg
}

func TestVersionHitReturnsAAndTXT(t *testing.T) {
	h := newHandler(t)
	msg := query(t, h, vQuery("pypi", "malicious-pkg", "1.0.0", zone), miekgdns.TypeA)

	if msg.Rcode != miekgdns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", msg.Rcode)
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
				t.Errorf("A = %v, want 127.0.0.2", r.A)
			}
		case *miekgdns.TXT:
			gotTXT = true
			txt := strings.Join(r.Txt, "")
			if !strings.Contains(txt, "MAL-2024-001") {
				t.Errorf("TXT %q missing OSV ID", txt)
			}
			if !strings.Contains(txt, "lvl=version") {
				t.Errorf("TXT %q missing lvl=version", txt)
			}
		}
	}
	if !gotA {
		t.Error("missing A record")
	}
	if !gotTXT {
		t.Error("missing TXT record")
	}
}

func TestPackageHitReturnsAAndTXT(t *testing.T) {
	h := newHandler(t)
	msg := query(t, h, pQuery("npm", "@scope/scoped-evil", zone), miekgdns.TypeA)

	if msg.Rcode != miekgdns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", msg.Rcode)
	}
	var gotTXT bool
	for _, rr := range msg.Answer {
		if r, ok := rr.(*miekgdns.TXT); ok {
			gotTXT = true
			txt := strings.Join(r.Txt, "")
			if !strings.Contains(txt, "lvl=package") {
				t.Errorf("TXT %q missing lvl=package", txt)
			}
		}
	}
	if !gotTXT {
		t.Error("missing TXT record")
	}
}

func TestMissReturnsNXDOMAIN(t *testing.T) {
	h := newHandler(t)
	msg := query(t, h, vQuery("pypi", "clean-pkg", "1.0.0", zone), miekgdns.TypeA)
	if msg.Rcode != miekgdns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", msg.Rcode)
	}
}

// testResponseWriter captures the DNS response written by the handler.
type testResponseWriter struct {
	msg *miekgdns.Msg
}

func (w *testResponseWriter) WriteMsg(m *miekgdns.Msg) error { w.msg = m; return nil }
func (w *testResponseWriter) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (w *testResponseWriter) RemoteAddr() net.Addr           { return &net.UDPAddr{} }
func (w *testResponseWriter) Write(b []byte) (int, error)    { return len(b), nil }
func (w *testResponseWriter) Close() error                   { return nil }
func (w *testResponseWriter) TsigStatus() error              { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)            {}
func (w *testResponseWriter) Hijack()                        {}
