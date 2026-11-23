package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	FeishuWebhook   string `json:"feishu_webhook"`
	FeishuSecret    string `json:"feishu_secret"`
	NVDAPIKey       string `json:"nvd_api_key"`
	Interval        string `json:"interval"`
	StateFile       string `json:"state_file"`
	DBFile          string `json:"db_file"`
	WebAddr         string `json:"web_addr"`
	PublicBaseURL   string `json:"public_base_url"`
	NotifyWhenEmpty *bool  `json:"notify_when_empty"`
}

func (c Config) SendWhenEmpty() bool {
	if c.NotifyWhenEmpty == nil {
		return false
	}
	return *c.NotifyWhenEmpty
}

func Load(path string) (Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, fmt.Errorf("未找到 %s，请复制 config.example.json 为 config.json 并填写 feishu_webhook", path)
		}
		return Config{}, err
	}

	var cfg Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Config{}, fmt.Errorf("解析 %s: %w", path, err)
	}
	if v := strings.TrimSpace(os.Getenv("FEISHU_WEBHOOK")); v != "" {
		cfg.FeishuWebhook = v
	}
	if v := os.Getenv("FEISHU_SECRET"); v != "" {
		cfg.FeishuSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("NVD_API_KEY")); v != "" {
		cfg.NVDAPIKey = v
	}
	cfg.FeishuWebhook = strings.TrimSpace(cfg.FeishuWebhook)
	cfg.FeishuSecret = strings.TrimSpace(cfg.FeishuSecret)
	cfg.NVDAPIKey = strings.TrimSpace(cfg.NVDAPIKey)
	if cfg.Interval == "" {
		cfg.Interval = "2h"
	}
	if cfg.StateFile == "" {
		cfg.StateFile = "state.json"
	}
	if cfg.DBFile == "" {
		cfg.DBFile = "cve.db"
	}
	if cfg.WebAddr == "" {
		cfg.WebAddr = ":12313"
	}
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = "http://127.0.0.1:12313"
	}
	cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	pageURL, err := url.Parse(cfg.PublicBaseURL)
	if err != nil || (pageURL.Scheme != "http" && pageURL.Scheme != "https") || pageURL.Host == "" {
		return Config{}, errors.New("public_base_url 必须是 http 或 https 地址")
	}
	if cfg.FeishuWebhook == "" {
		return Config{}, errors.New("未配置飞书 webhook：在 config.json 填写 feishu_webhook，或设置环境变量 FEISHU_WEBHOOK")
	}
	u, err := url.Parse(cfg.FeishuWebhook)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Config{}, errors.New("feishu_webhook 必须是 https 地址")
	}
	return cfg, nil
}
