package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// DenyRecord is one collapsed entry in the visa service's recent-denies window.
// Records are collapsed on (source_addr, dest_addr, protocol, dest_port,
// deny_code). LastDenyMS is epoch MILLISECONDS, unlike the seconds used by
// every other admin endpoint.
type DenyRecord struct {
	SourceAddr string `json:"source_addr"`
	DestAddr   string `json:"dest_addr"`
	Protocol   uint8  `json:"protocol"`
	DestPort   uint16 `json:"dest_port"` // the ICMP code for ICMP traffic
	ICMPType   *uint8 `json:"icmp_type"` // the ICMP type for ICMP traffic; nil (JSON null) otherwise
	Count      uint64 `json:"count"`
	LastDenyMS uint64 `json:"last_deny_ms"`
	DenyCode   string `json:"deny_code"` // open string: a new server code must not break decoding
}

// GetDenies returns the most recently denied traffic, newest request first.
func (c *Client) GetDenies(ctx context.Context, limit int) ([]DenyRecord, error) {
	if limit < 1 {
		return nil, fmt.Errorf("Get denies: limit must be at least 1, got %d", limit)
	}

	query := url.Values{"limit": {fmt.Sprint(limit)}}

	resp, err := c.Get(ctx, "/admin/visas/denies?"+query.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Get denies: %s", resp.Status)
	}

	// Ordered by deny recency, not by timestamp: a clock change can leave
	// last_deny_ms out of order. Keep the server's order regardless.
	var records []DenyRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("Decode denies: %w", err)
	}

	return records, nil
}
