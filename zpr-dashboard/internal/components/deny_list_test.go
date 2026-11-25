package components

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
)

// denyTestActors covers a named actor, a second named actor, and an actor
// whose CN is empty so the address must survive.
var denyTestActors = []dataplane.ActorDescriptor{
	{CName: "node-nyc", ZprAddress: "fd5a:5052:1000::1"},
	{CName: "node-lon", ZprAddress: "fd5a:5052:1000::9"},
	{CName: "", ZprAddress: "fd5a:5052:1000::5"},
}

// TestDenyProtocol checks named protocols, the decimal fallback, that a zero
// port or ICMP code is preserved rather than rendered as "any", and that an
// ICMP deny shows its type next to its code when the service reports one.
func TestDenyProtocol(t *testing.T) {
	echoRequest, neighborSolicitation := uint8(8), uint8(135)
	cases := []struct {
		protocol uint8
		destPort uint16
		icmpType *uint8
		want     string
	}{
		{6, 443, nil, "TCP/443"},
		{17, 53, nil, "UDP/53"},
		{1, 0, &echoRequest, "ICMP/T8 C0"},
		{58, 0, &neighborSolicitation, "ICMPv6/T135 C0"},
		{1, 0, nil, "ICMP/C0"}, // a malformed type the service could not report
		{58, 3, nil, "ICMPv6/C3"},
		{200, 8080, nil, "200/8080"},
		{6, 0, nil, "TCP/0"},
	}

	for _, c := range cases {
		record := dataplane.DenyRecord{Protocol: c.protocol, DestPort: c.destPort, ICMPType: c.icmpType}
		if got := denyProtocol(record); got != c.want {
			t.Errorf("denyProtocol(%d, %d, %v) = %q, want %q", c.protocol, c.destPort, c.icmpType, got, c.want)
		}
	}
}

// TestFormatDenyTime checks a known epoch-millisecond value formats in local
// time, and that a value beyond int64 falls back to raw milliseconds.
func TestFormatDenyTime(t *testing.T) {
	// Pin a non-UTC zone so the expected string does not depend on the test
	// machine and an accidental .UTC() conversion cannot pass.
	saved := time.Local
	time.Local = time.FixedZone("TEST", 5*60*60+30*60)
	t.Cleanup(func() { time.Local = saved })

	if got, want := formatDenyTime(1785604630203), "08-01 22:47:10.203"; got != want {
		t.Errorf("formatDenyTime = %q, want %q", got, want)
	}

	if got, want := formatDenyTime(math.MaxUint64), "18446744073709551615ms"; got != want {
		t.Errorf("out-of-range formatDenyTime = %q, want %q", got, want)
	}
}

// TestDenyEndpointUsesActorCN checks a known address renders as its CN, an
// unknown address stays visible, and an empty CN falls back to the address.
func TestDenyEndpointUsesActorCN(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"fd5a:5052:1000::1", "node-nyc"},
		{"fd5a:5052:1000::7", "fd5a:5052:1000::7"}, // unknown to the snapshot
		{"fd5a:5052:1000::5", "fd5a:5052:1000::5"}, // known, but no CN
	}

	for _, c := range cases {
		if got := endpointLabel(c.addr, denyTestActors); got != c.want {
			t.Errorf("endpointLabel(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// TestDenyListRendersRows checks the panel title, subtitle, and row values
// reach the output, with addresses replaced by actor CNs where known.
func TestDenyListRendersRows(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("TEST", 5*60*60+30*60)
	t.Cleanup(func() { time.Local = saved })

	records := []dataplane.DenyRecord{
		{SourceAddr: "fd5a:5052:1000::1", DestAddr: "fd5a:5052:1000::9", Protocol: 6, DestPort: 443, Count: 2, LastDenyMS: 1785604630203, DenyCode: "NoMatch"},
		{SourceAddr: "fd5a:5052:1000::7", DestAddr: "fd5a:5052:1000::5", Protocol: 1, DestPort: 0, Count: 1, LastDenyMS: 1785604630203, DenyCode: "Denied"},
	}

	out := ansi.Strip(DenyList(160, 20, records, denyTestActors, nil))

	for _, want := range []string{
		"Visa Denials",
		"2 recent denials, newest first",
		"08-01 22:47:10.203",
		"node-nyc", "node-lon",
		"fd5a:5052:1000::7", "fd5a:5052:1000::5",
		"TCP/443", "ICMP/C0",
		"NoMatch", "Denied",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output", want)
		}
	}
}

// TestDenyListEmptyState checks the startup case, which is normal because the
// service's deny window is in memory and starts empty.
func TestDenyListEmptyState(t *testing.T) {
	out := ansi.Strip(DenyList(160, 20, nil, denyTestActors, nil))

	if !strings.Contains(out, "No visa denials recorded") {
		t.Errorf("expected empty-state note, got %q", out)
	}
	if !strings.Contains(out, "0 recent denials, newest first") {
		t.Errorf("expected zero-count subtitle, got %q", out)
	}
}

// TestDenyListShowsICMPTypeAtNarrowWidth checks that at a 100-column panel two
// ICMPv6 denies that differ only in type stay distinguishable: the protocol
// column must show the whole type and code, not truncate them, up to the
// longest possible label (type 255, code 255).
func TestDenyListShowsICMPTypeAtNarrowWidth(t *testing.T) {
	echoRequest, neighborSolicitation, widest := uint8(128), uint8(135), uint8(255)
	records := []dataplane.DenyRecord{
		{SourceAddr: "fd5a:5052:1000::1", DestAddr: "fd5a:5052:1000::9", Protocol: 58, DestPort: 0, ICMPType: &neighborSolicitation, Count: 3, LastDenyMS: 1785604630203, DenyCode: "NoMatch"},
		{SourceAddr: "fd5a:5052:1000::1", DestAddr: "fd5a:5052:1000::9", Protocol: 58, DestPort: 0, ICMPType: &echoRequest, Count: 1, LastDenyMS: 1785604630000, DenyCode: "NoMatch"},
		{SourceAddr: "fd5a:5052:1000::1", DestAddr: "fd5a:5052:1000::9", Protocol: 58, DestPort: 255, ICMPType: &widest, Count: 1, LastDenyMS: 1785604620000, DenyCode: "NoMatch"},
	}

	out := ansi.Strip(DenyList(100, 20, records, denyTestActors, nil))

	for _, record := range records {
		want := denyProtocol(record)
		if !strings.Contains(out, want) {
			t.Errorf("expected %q untruncated in the 100-column table:\n%s", want, out)
		}
	}
}
