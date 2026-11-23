package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Bot struct {
	webhook string
	secret  string
	http    *http.Client
}

func New(webhook, secret string) *Bot {
	return &Bot{
		webhook: webhook,
		secret:  secret,
		http:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (b *Bot) Send(ctx context.Context, text string) error {
	text = limitRunes(text, 3500)
	payload := map[string]any{
		"msg_type": "text",
		"content": map[string]string{
			"text": text,
		},
	}
	if b.secret != "" {
		timestamp := time.Now().Unix()
		payload["timestamp"] = strconv.FormatInt(timestamp, 10)
		payload["sign"] = feishuSign(b.secret, timestamp)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("飞书 http %d: %s", resp.StatusCode, clip(string(respBody), 300))
	}
	var result struct {
		Code          *int   `json:"code"`
		Msg           string `json:"msg"`
		StatusCode    *int   `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("解析飞书响应: %w", err)
	}
	if result.Code != nil && *result.Code != 0 {
		return fmt.Errorf("飞书返回 code=%d %s", *result.Code, result.Msg)
	}
	if result.StatusCode != nil && *result.StatusCode != 0 {
		return fmt.Errorf("飞书返回 StatusCode=%d %s", *result.StatusCode, result.StatusMessage)
	}
	if result.Code == nil && result.StatusCode == nil {
		return fmt.Errorf("飞书响应无法确认是否成功: %s", clip(string(respBody), 300))
	}
	return nil
}

func feishuSign(secret string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(fmt.Sprintf("%d\n%s", timestamp, secret)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func limitRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "\n…（内容已截断）"
}
