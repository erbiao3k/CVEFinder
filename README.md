# CVEFinder

按固定产品名单从 NVD 拉取漏洞，清洗后写入 SQLite。网页查看详情；只有出现新的匹配漏洞时，才向飞书发一条汇总。

## 准备

```bash
cp config.example.json config.json
```

在 `config.json` 填写 `feishu_webhook`。机器人开启了签名校验时，再填 `feishu_secret`。`nvd_api_key` 可以留空。要在手机上打开飞书里的链接，把 `public_base_url` 改成这台机器的访问地址。

监听的产品在 `internal/watch/watch.go` 的 `Default`。

## 运行

```bash
go run ./cmd/cvefinder
```

启动后先拉取最近 7 天，之后按 `interval`（默认 2 小时）增量检查。网页默认是 http://127.0.0.1:12313 。

## 编译

```bash
# Windows
go build -o CVEFinder.exe ./cmd/cvefinder

# Linux amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o CVEFinder-linux-amd64 ./cmd/cvefinder
```

Linux 上把 `config.json` 和可执行文件放在同一目录：

```bash
chmod +x CVEFinder-linux-amd64
./CVEFinder-linux-amd64
```

## 不要提交

`config.json` 含飞书 webhook。`cve.db`、`state.json` 和编译出的二进制已写在 `.gitignore` 里。
