package dns

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	miekgdns "github.com/miekg/dns"
	"github.com/chromatic/malicious-packages-dns/internal/store"
)

// Storer is the interface the Handler needs from the store.
type Storer interface {
	LookupHash(verLabel, pkgLabel, bucket string) (store.Result, bool)
	Close() error
}

// Handler implements miekg/dns.Handler.
type Handler struct {
	store   atomic.Pointer[storerWrapper]
	zone    string
	ttlHit  uint32
	ttlMiss uint32
}

// storerWrapper boxes the interface into a concrete pointer for atomic.Pointer.
type storerWrapper struct{ s Storer }

// NewHandler returns a Handler wired to the given store.
func NewHandler(s Storer, zone string, ttlHit, ttlMiss uint32) *Handler {
	h := &Handler{zone: zone, ttlHit: ttlHit, ttlMiss: ttlMiss}
	h.store.Store(&storerWrapper{s})
	return h
}

// SwapStore atomically replaces the store and returns the old one for closing.
func (h *Handler) SwapStore(s Storer) Storer {
	old := h.store.Swap(&storerWrapper{s})
	return old.s
}

// ServeDNS handles incoming DNS queries.
func (h *Handler) ServeDNS(w miekgdns.ResponseWriter, req *miekgdns.Msg) {
	msg := new(miekgdns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	if len(req.Question) == 0 {
		msg.Rcode = miekgdns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}

	q := req.Question[0]
	verLabel, pkgLabel, sublabel, ok := parseLabels(q.Name, h.zone)
	if !ok {
		msg.Rcode = miekgdns.RcodeNameError
		w.WriteMsg(msg)
		return
	}

	switch sublabel {
	case "v", "p":
	default:
		msg.Rcode = miekgdns.RcodeNameError
		w.WriteMsg(msg)
		return
	}

	result, found := h.store.Load().s.LookupHash(verLabel, pkgLabel, sublabel)
	if !found {
		msg.Rcode = miekgdns.RcodeNameError
		h.addSOA(msg)
		w.WriteMsg(msg)
		return
	}

	msg.Answer = append(msg.Answer,
		&miekgdns.A{
			Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: h.ttlHit},
			A:   net.ParseIP("127.0.0.2"),
		},
		&miekgdns.TXT{
			Hdr: miekgdns.RR_Header{Name: q.Name, Rrtype: miekgdns.TypeTXT, Class: miekgdns.ClassINET, Ttl: h.ttlHit},
			Txt: []string{fmt.Sprintf("osv=%s lvl=%s", result.OSVID, result.MatchLevel)},
		},
	)
	w.WriteMsg(msg)
}

func (h *Handler) addSOA(msg *miekgdns.Msg) {
	msg.Ns = append(msg.Ns, &miekgdns.SOA{
		Hdr:     miekgdns.RR_Header{Name: h.zone, Rrtype: miekgdns.TypeSOA, Class: miekgdns.ClassINET, Ttl: h.ttlMiss},
		Ns:      "ns1." + h.zone,
		Mbox:    "hostmaster." + h.zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  h.ttlMiss,
	})
}

// parseLabels extracts labels from a DNS query name.
//
// .v. format: <verLabel>.<pkgLabel>.v.<zone>  (version query)
// .p. format: <pkgLabel>.p.<zone>             (package query)
//
// Returns (verLabel, pkgLabel, sublabel, ok).
// For .p. queries, verLabel is empty.
func parseLabels(qname, zone string) (verLabel, pkgLabel, sublabel string, ok bool) {
	if !strings.HasSuffix(qname, zone) {
		return "", "", "", false
	}
	prefix := strings.TrimSuffix(strings.TrimSuffix(qname, zone), ".")
	parts := strings.Split(prefix, ".")
	switch {
	case len(parts) == 3 && parts[2] == "v":
		// <verLabel>.<pkgLabel>.v
		if len(parts[0]) == 0 || len(parts[1]) == 0 {
			return "", "", "", false
		}
		return parts[0], parts[1], "v", true
	case len(parts) == 2 && parts[1] == "p":
		// <pkgLabel>.p
		if len(parts[0]) != 13 {
			return "", "", "", false
		}
		return "", parts[0], "p", true
	default:
		return "", "", "", false
	}
}
