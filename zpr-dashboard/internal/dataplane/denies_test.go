package dataplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// TestGetDeniesRequestAndDecode checks the request path, query, and API key
// header, that every field decodes, and that the server's order is preserved.
func TestGetDeniesRequestAndDecode(t *testing.T) {
	var gotPath, gotKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		gotKey = r.Header.Get(apiKeyHeader)
		w.Write([]byte(`[
			{"source_addr":"fd5a:5052:1000::1","dest_addr":"fd5a:5052:1000::9","protocol":6,"dest_port":443,"icmp_type":null,"count":2,"last_deny_ms":1785604630203,"deny_code":"NoMatch"},
			{"source_addr":"fd5a:5052:1000::2","dest_addr":"fd5a:5052:1000::8","protocol":1,"dest_port":0,"icmp_type":8,"count":1,"last_deny_ms":1785604630000,"deny_code":"Denied"}
		]`))
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, apiKey: "test-key", http: srv.Client()}

	got, err := c.GetDenies(context.Background(), 100)
	if err != nil {
		t.Fatalf("GetDenies: %v", err)
	}

	if gotPath != "/admin/visas/denies?limit=100" {
		t.Errorf("path: got %q", gotPath)
	}
	if gotKey != "test-key" {
		t.Errorf("api key header: got %q", gotKey)
	}

	// Newest request first, which is not the same as timestamp order.
	// icmp_type is null for TCP and the ICMP type (8, echo request) for ICMP.
	echoRequest := uint8(8)
	want := []DenyRecord{
		{SourceAddr: "fd5a:5052:1000::1", DestAddr: "fd5a:5052:1000::9", Protocol: 6, DestPort: 443, ICMPType: nil, Count: 2, LastDenyMS: 1785604630203, DenyCode: "NoMatch"},
		{SourceAddr: "fd5a:5052:1000::2", DestAddr: "fd5a:5052:1000::8", Protocol: 1, DestPort: 0, ICMPType: &echoRequest, Count: 1, LastDenyMS: 1785604630000, DenyCode: "Denied"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		// DeepEqual compares the ICMPType values, not the pointers.
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("record %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestGetDeniesRejectsBadLimit checks a limit below 1 fails before any request
// is sent, so the dashboard cannot ask for the service's whole window.
func TestGetDeniesRejectsBadLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request sent despite invalid limit")
	}))
	t.Cleanup(srv.Close)

	c := &Client{baseURL: srv.URL, http: srv.Client()}

	for _, limit := range []int{0, -1} {
		_, err := c.GetDenies(context.Background(), limit)
		if err == nil {
			t.Errorf("limit %d: want error, got nil", limit)
			continue
		}
		if !strings.Contains(err.Error(), "Get denies") {
			t.Errorf("limit %d: error %q lacks operation name", limit, err)
		}
	}
}
