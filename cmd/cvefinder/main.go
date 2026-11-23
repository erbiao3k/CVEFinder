package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"CVEFinder/internal/config"
	"CVEFinder/internal/cve"
	"CVEFinder/internal/notify"
	"CVEFinder/internal/nvd"
	"CVEFinder/internal/store"
	"CVEFinder/internal/watch"
	"CVEFinder/internal/web"
)

func main() {
	log.SetFlags(log.LstdFlags)
	configPath := flag.String("config", "config.json", "配置文件路径")
	once := flag.Bool("once", false, "只检测一次后退出")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil {
		log.Fatalf("interval 无法解析: %v", err)
	}
	if interval < time.Minute {
		log.Fatal("interval 至少为 1 分钟")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	watcher := watch.New(watch.Default())
	source := nvd.New(cfg.NVDAPIKey)
	bot := notify.New(cfg.FeishuWebhook, cfg.FeishuSecret)
	states := store.OpenState(cfg.StateFile)
	db, err := store.Open(cfg.DBFile)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()
	if err := web.Start(ctx, cfg.WebAddr, db); err != nil {
		log.Fatalf("网页监听失败: %v", err)
	}

	log.Printf("网页 %s", cfg.PublicBaseURL)
	log.Printf("开始监听，间隔 %s，启动范围最近 7 天，产品：%s", interval, strings.Join(watcher.Names(), "、"))
	err = runOnce(ctx, cfg, source, bot, watcher, states, db, startupLookback)
	if *once {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	if err != nil {
		log.Printf("检测失败: %v", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("已停止")
			return
		case <-ticker.C:
			if err := runOnce(ctx, cfg, source, bot, watcher, states, db, 0); err != nil {
				log.Printf("检测失败: %v", err)
			}
		}
	}
}

const startupLookback = 7 * 24 * time.Hour

func queryWindow(end, cursor time.Time, lookback time.Duration) time.Time {
	var start time.Time
	if lookback > 0 {
		start = end.Add(-lookback)
		if !cursor.IsZero() && cursor.Before(start) {
			start = cursor
		}
	} else {
		start = cursor
		if start.IsZero() || !start.Before(end) {
			start = end.Add(-2 * time.Hour)
		}
		if !cursor.IsZero() {
			start = start.Add(-2 * time.Minute)
		}
	}
	if end.Sub(start) > 119*24*time.Hour {
		start = end.Add(-119 * 24 * time.Hour)
	}
	return start
}

func runOnce(parent context.Context, cfg config.Config, source *nvd.Client, bot *notify.Bot, watcher *watch.Watcher, states *store.StateFile, db *store.DB, lookback time.Duration) error {
	timeout := 15 * time.Minute
	if lookback > 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	st, err := states.Load()
	if err != nil {
		return err
	}
	end := time.Now().UTC().Add(-time.Minute)
	queryStart := queryWindow(end, st.Cursor, lookback)

	cves, err := source.ModifiedBetween(ctx, queryStart, end)
	if err != nil {
		title := "漏洞例行报告"
		if lookback > 0 {
			title = "漏洞启动报告"
		}
		text := title + "\n检测失败，游标未推进，下次检查会重试。\n原因 " + cve.OneLine(err.Error(), 300)
		if sendErr := bot.Send(ctx, text); sendErr != nil {
			return fmt.Errorf("拉取失败: %v；通知失败: %w", err, sendErr)
		}
		return err
	}

	var records []cve.Record
	var hits []notify.Hit
	for _, item := range cves {
		products := watcher.Match(item)
		record, ok := cve.Clean(item, products)
		if !ok {
			continue
		}
		records = append(records, record)
		if _, seen := st.Notified[record.ID]; seen {
			continue
		}
		hits = append(hits, notify.Hit{
			ID:       record.ID,
			Severity: record.Severity,
			Score:    record.Score,
			Products: record.Products,
		})
	}
	if err := db.Upsert(ctx, records); err != nil {
		return err
	}
	notify.Sort(hits)
	log.Printf("窗口 %s ~ %s，NVD %d 条，入库 %d 条，新增 %d 条", nvd.FormatTime(queryStart), nvd.FormatTime(end), len(cves), len(records), len(hits))

	if len(hits) == 0 && !cfg.SendWhenEmpty() {
		log.Printf("没有新增漏洞，不发送飞书")
		st.Cursor = end
		return states.Save(st)
	}

	text := notify.Summary(queryStart, end, hits, len(watcher.Names()), cfg.PublicBaseURL)
	if err := bot.Send(ctx, text); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, hit := range hits {
		st.Notified[hit.ID] = now
	}
	st.Cursor = end
	store.Prune(&st, time.Now().UTC())
	return states.Save(st)
}
