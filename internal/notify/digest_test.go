package notify

import (
	"strings"
	"testing"
	"time"
)

func TestSummaryOmitsCVEDetails(t *testing.T) {
	start := time.Date(2026, 11, 16, 2, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC)
	empty := Summary(start, end, nil, 28, "http://127.0.0.1:12313")
	if !strings.Contains(empty, "没有新增") || !strings.Contains(empty, "http://127.0.0.1:12313") {
		t.Fatalf("empty = %q", empty)
	}
	hits := []Hit{
		{ID: "CVE-2024-1000", Severity: "CRITICAL", Score: 9.8, Products: []string{"Nginx"}},
		{ID: "CVE-2024-1001", Severity: "HIGH", Score: 7.5, Products: []string{"Nginx", "Linux 内核"}},
	}
	text := Summary(start, end, hits, 28, "http://127.0.0.1:12313")
	if strings.Contains(text, "CVE-2024") {
		t.Fatalf("summary leaked cve id: %s", text)
	}
	for _, part := range []string{"新增 2 条", "严重 1", "高危 1", "Nginx 2", "Linux 内核 1", "http://127.0.0.1:12313"} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}
