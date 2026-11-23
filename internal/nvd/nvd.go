package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type Client struct {
	apiKey string
	http   *http.Client
	gap    time.Duration
	last   time.Time
}

func New(apiKey string) *Client {
	gap := 6 * time.Second
	if strings.TrimSpace(apiKey) != "" {
		gap = 700 * time.Millisecond
	}
	return &Client{
		apiKey: strings.TrimSpace(apiKey),
		gap:    gap,
		http:   &http.Client{Timeout: 180 * time.Second},
	}
}

type CVE struct {
	ID             string          `json:"id"`
	VulnStatus     string          `json:"vulnStatus"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	Descriptions   []Text          `json:"descriptions"`
	Metrics        Metrics         `json:"metrics"`
	Configurations []Configuration `json:"configurations"`
	References     []Ref           `json:"references"`
}

type Ref struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	CPEMatch []CPEMatch `json:"cpeMatch"`
	Children []Node     `json:"children"`
}

type CPEMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

type Text struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	V40 []Metric `json:"cvssMetricV40"`
	V31 []Metric `json:"cvssMetricV31"`
	V30 []Metric `json:"cvssMetricV30"`
	V2  []Metric `json:"cvssMetricV2"`
}

type Metric struct {
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdPage struct {
	items []CVE
	total int
}

func (c *Client) ModifiedBetween(ctx context.Context, start, end time.Time) ([]CVE, error) {
	if !start.Before(end) {
		return nil, nil
	}
	const pageSize = 2000
	var all []CVE
	for pageNo := 0; pageNo < 50; pageNo++ {
		startIndex := pageNo * pageSize
		q := url.Values{}
		q.Set("lastModStartDate", FormatTime(start))
		q.Set("lastModEndDate", FormatTime(end))
		q.Set("resultsPerPage", strconv.Itoa(pageSize))
		q.Set("startIndex", strconv.Itoa(startIndex))
		endpoint := nvdEndpoint + "?" + q.Encode()

		body, err := c.get(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		page, err := parseNVD(body)
		if err != nil {
			return nil, err
		}
		all = append(all, page.items...)
		if len(page.items) == 0 || startIndex+len(page.items) >= page.total {
			break
		}
	}
	return all, nil
}

func parseNVD(body []byte) (nvdPage, error) {
	var raw struct {
		Vulnerabilities []struct {
			CVE CVE `json:"cve"`
		} `json:"vulnerabilities"`
		TotalResults int `json:"totalResults"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nvdPage{}, fmt.Errorf("解析 NVD 响应: %w", err)
	}
	page := nvdPage{total: raw.TotalResults}
	for _, item := range raw.Vulnerabilities {
		if item.CVE.ID == "" {
			continue
		}
		page.items = append(page.items, item.CVE)
	}
	return page, nil
}

func (c *Client) get(ctx context.Context, endpoint string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt) * 15 * time.Second
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		if err := c.pace(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "CVEFinder/1.0")
		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("nvd http %d: %s", resp.StatusCode, clip(string(body), 240))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("nvd http %d: %s", resp.StatusCode, clip(string(body), 300))
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("nvd 请求失败")
	}
	return nil, lastErr
}

func (c *Client) pace(ctx context.Context) error {
	var wait time.Duration
	if !c.last.IsZero() {
		wait = c.gap - time.Since(c.last)
	}
	if wait < 0 {
		wait = 0
	}
	c.last = time.Now().Add(wait)
	if wait == 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000")
}

func (c CVE) Description() string {
	fallback := ""
	for _, item := range c.Descriptions {
		switch strings.ToLower(item.Lang) {
		case "zh", "zh-cn", "zh-hans":
			return item.Value
		case "en":
			fallback = item.Value
		}
	}
	if fallback != "" {
		return fallback
	}
	if len(c.Descriptions) > 0 {
		return c.Descriptions[0].Value
	}
	return ""
}

func (c CVE) Severity() (string, float64) {
	groups := [][]Metric{c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2}
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		metric := group[0]
		sev := metric.CVSSData.BaseSeverity
		if sev == "" {
			sev = metric.BaseSeverity
		}
		if sev == "" && metric.CVSSData.BaseScore > 0 {
			sev = scoreSeverity(metric.CVSSData.BaseScore)
		}
		return strings.ToUpper(sev), metric.CVSSData.BaseScore
	}
	return "", 0
}

func scoreSeverity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return ""
	}
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n]
}
