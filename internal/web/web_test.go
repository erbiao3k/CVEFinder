package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"CVEFinder/internal/cve"
	"CVEFinder/internal/store"
)

func TestWebPages(t *testing.T) {
	db := seedTestDB(t)
	server := httptest.NewServer(Handler(db))
	defer server.Close()

	body := getBody(t, server.URL+"/")
	if !strings.Contains(body, "CVE-2024-1000") || !strings.Contains(body, "CVE-2024-1001") {
		t.Fatalf("list missing rows: %s", body)
	}
	high := getBody(t, server.URL+"/?severity=HIGH")
	if strings.Contains(high, "CVE-2024-1000") || !strings.Contains(high, "CVE-2024-1001") {
		t.Fatalf("filter failed: %s", high)
	}
	detail := getBody(t, server.URL+"/cve/CVE-2024-1000")
	if !strings.Contains(detail, "nginx issue") || !strings.Contains(detail, "NVD 原文") || !strings.Contains(detail, "补丁") || !strings.Contains(detail, "https://example.com/nginx.patch") || !strings.Contains(detail, "厂商公告") {
		t.Fatalf("detail failed: %s", detail)
	}
	if !strings.Contains(body, "补丁、厂商公告") {
		t.Fatalf("list missing ref labels: %s", body)
	}
}

func seedTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "cve.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	err = db.Upsert(context.Background(), []cve.Record{
		{ID: "CVE-2024-1000", Severity: "CRITICAL", Score: 9.8, Products: []string{"Nginx"}, Summary: "nginx issue", Status: "Analyzed", Modified: "2024-03-02T01:02:03Z", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1000", References: []cve.Reference{
			{URL: "https://example.com/nginx.patch", Tags: []string{"Patch"}},
			{URL: "https://example.com/nginx-advisory", Tags: []string{"Vendor Advisory"}},
		}},
		{ID: "CVE-2024-1001", Severity: "HIGH", Score: 8.1, Products: []string{"Nginx", "Linux 内核"}, Summary: "kernel issue", Status: "Analyzed", Modified: "2024-04-02T01:02:03Z", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s", res.StatusCode, body)
	}
	return string(body)
}
