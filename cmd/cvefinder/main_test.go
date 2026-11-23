package main

import (
	"testing"
	"time"
)

func TestQueryWindowStartupIsSevenDays(t *testing.T) {
	end := time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC)
	start := queryWindow(end, time.Time{}, startupLookback)
	if !start.Equal(end.Add(-7 * 24 * time.Hour)) {
		t.Fatalf("start = %s", start)
	}
	recent := end.Add(-time.Hour)
	start = queryWindow(end, recent, startupLookback)
	if !start.Equal(end.Add(-7 * 24 * time.Hour)) {
		t.Fatalf("recent cursor start = %s", start)
	}
	older := end.Add(-10 * 24 * time.Hour)
	start = queryWindow(end, older, startupLookback)
	if !start.Equal(older) {
		t.Fatalf("older cursor start = %s", start)
	}
}
