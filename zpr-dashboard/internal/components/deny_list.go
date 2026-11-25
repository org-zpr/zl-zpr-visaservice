package components

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/x/ansi"
	"neboagency.com/zpr-dashborad/internal/dataplane"
	"neboagency.com/zpr-dashborad/internal/styles"
	"neboagency.com/zpr-dashborad/internal/timefmt"
)

// IANA IP protocol numbers, matching admin-api-types.
const (
	ipProtoICMP     = 1
	ipProtoTCP      = 6
	ipProtoUDP      = 17
	ipProtoIPv6ICMP = 58
)

// Precision extension of the shared date-time layout: repeat-rate is the
// signal in this pane, so denials keep seconds and milliseconds.
const denyTimeLayout = timefmt.LayoutDateTime + ":05.000"

// DenyList renders the visa service's bounded recent-denials feed.
func DenyList(width, height int, records []dataplane.DenyRecord, actors []dataplane.ActorDescriptor, fetchErr error) string {
	content := styles.TitleStyle.Render("Visa Denials") + "\n"
	content += styles.SubtitleStyle.Render(
		fmt.Sprintf("%d recent %s, newest first", len(records), plural(len(records), "denial")),
	) + "\n"
	content += styles.Separator(width - 4)
	budget := height - panelChrome

	if fetchErr != nil && len(records) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelError(fetchErr), budget, panelBodyWidth(width)))
	}

	if len(records) == 0 {
		return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(panelNote("No visa denials recorded"), budget, panelBodyWidth(width)))
	}

	extra := 0
	if fetchErr != nil {
		extra = 1
	}

	fits, hidden := tableRowsThatFit(len(records), budget, extra)
	body := "\n" + denyTable(width, records[:fits], actors)

	if hidden > 0 {
		// Counts the fetched snapshot only; the API reports no server-side total.
		body += "\n" + styles.SubtitleStyle.Render(fmt.Sprintf("+%d more recent records", hidden))
	}

	if fetchErr != nil {
		body += "\n" + lipgloss.NewStyle().Foreground(styles.ColorRed).Render("last refresh failed: "+fetchErr.Error())
	}

	return styles.ContainerStyle.Height(height).Width(width).Render(content + clampLines(body, budget, panelBodyWidth(width)))
}

// denyTable lays out one row per deny record across the six deny columns.
func denyTable(width int, records []dataplane.DenyRecord, actors []dataplane.ActorDescriptor) string {
	size := width - 5

	whenSize := int(float32(size) * 0.23)
	sourceSize := int(float32(size) * 0.2)
	destSize := int(float32(size) * 0.2)
	protoSize := int(float32(size) * 0.17)
	reasonSize := int(float32(size) * 0.14)
	countSize := size - whenSize - sourceSize - destSize - protoSize - reasonSize

	widths := []int{whenSize, sourceSize, destSize, protoSize, reasonSize, countSize}
	columnWidth := func(col int) int {
		if col < len(widths) {
			return widths[col]
		}
		return countSize
	}

	t := table.New().
		Width(size).
		Border(lipgloss.HiddenBorder()).
		Headers("Last denied", "Source", "Destination", "Proto / Dst", "Reason", "Count").
		BorderHeader(false).
		BorderTop(false).
		BorderBottom(false).
		BorderLeft(false).
		BorderColumn(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			s := lipgloss.NewStyle()

			if row == table.HeaderRow {
				s = s.
					Foreground(styles.ColorBlue).
					Bold(true).
					Border(lipgloss.RoundedBorder(), false, false, true, false).
					BorderForeground(styles.ColorDimmed)
			} else {
				s = s.Foreground(styles.ColorFg)

				switch {
				case col == 4:
					s = s.Foreground(styles.ColorRed)
				case col == 5 && row < len(records) && records[row].Count > 1:
					// Repeated traffic is the interesting case.
					s = s.Foreground(styles.ColorYellow)
				}
			}

			return s.Width(columnWidth(col)).MaxWidth(columnWidth(col))
		})

	for _, record := range records {
		t.Row(
			ansi.Truncate(formatDenyTime(record.LastDenyMS), whenSize, "..."),
			ansi.Truncate(endpointLabel(record.SourceAddr, actors), sourceSize, "..."),
			ansi.Truncate(endpointLabel(record.DestAddr, actors), destSize, "..."),
			ansi.Truncate(denyProtocol(record), protoSize, "..."),
			ansi.Truncate(orDash(record.DenyCode), reasonSize, "..."),
			ansi.Truncate(strconv.FormatUint(record.Count, 10), countSize, "..."),
		)
	}

	return t.Render()
}

// endpointLabel labels a ZPR address with its actor's CN when the current
// actor snapshot knows the address and the actor has one, and returns the
// address otherwise.
func endpointLabel(addr string, actors []dataplane.ActorDescriptor) string {
	if actor, ok := actorByAddr(actors, addr); ok && actor.CName != "" {
		return actorLabel(actor)
	}

	return orDash(addr)
}

// denyProtocol renders a deny's protocol with its destination port, or for
// ICMP its type and code, compactly as "ICMPv6/T135 C0". Denies that differ
// only in ICMP type must stay distinguishable, so the longest form,
// "ICMPv6/T255 C255", is kept within the 16-character protocol column of a
// 100-column panel. The type is left out ("ICMPv6/C3") when the service
// reports none (a malformed ICMP type it could not represent).
func denyProtocol(record dataplane.DenyRecord) string {
	name := strconv.Itoa(int(record.Protocol))
	icmp := false

	switch record.Protocol {
	case ipProtoICMP:
		name, icmp = "ICMP", true
	case ipProtoTCP:
		name = "TCP"
	case ipProtoUDP:
		name = "UDP"
	case ipProtoIPv6ICMP:
		name, icmp = "ICMPv6", true
	}

	if icmp && record.ICMPType != nil {
		return fmt.Sprintf("%s/T%d C%d", name, *record.ICMPType, record.DestPort)
	}
	if icmp {
		return fmt.Sprintf("%s/C%d", name, record.DestPort)
	}

	return fmt.Sprintf("%s/%d", name, record.DestPort)
}

// formatDenyTime renders epoch milliseconds as local time. Values too large
// for an int64 fall back to the raw number rather than overflowing the cast.
func formatDenyTime(epochMS uint64) string {
	if epochMS > math.MaxInt64 {
		return fmt.Sprintf("%dms", epochMS)
	}

	return time.UnixMilli(int64(epochMS)).Format(denyTimeLayout)
}
