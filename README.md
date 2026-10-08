# smartdns-rules

把 [flyzstu/sing-box-rules](https://github.com/flyzstu/sing-box-rules) 的 geosite
（sing-box rule-set JSON）转成 [smartdns](https://github.com/pymumu/smartdns) 的
`domain-set` 纯文本列表，供路由器做 DNS 分流（国内直连 / 境外经代理解析）。

每日由 GitHub Actions 定时构建并发布。

## 产物

| 文件 | 内容 |
|---|---|
| `cn.lst` | 国内域名（来自 `geosite-cn` + `geosite-tld-cn`），一行一域名 |
| `not-cn.lst` | 非国内域名（来自 `geosite-geolocation-!cn`） |
| `regex-*.txt` | 源里的 `domain_regex`（仅归档；smartdns 不支持正则域匹配，未纳入 `.lst`） |
| `manifest.json` | 行数、sha256、来源、构建时间 |
| `*.lst.sha256` | 校验和 |

## 获取

- 分支（滚动）：
  - `https://raw.githubusercontent.com/wx2020/smartdns-rules/data/cn.lst`
  - `https://raw.githubusercontent.com/wx2020/smartdns-rules/data/not-cn.lst`
- Release（最新）：
  - `https://github.com/wx2020/smartdns-rules/releases/latest/download/cn.lst`

## 转换规则

- 取 rule-set 的 `domain` 与 `domain_suffix`：`domain_suffix` 去掉前导点，
  统一作为 smartdns 后缀匹配行（smartdns 采用域名后缀匹配）。
- 归一化：小写、去空白、丢弃含 `*()^$[]?\+|` 等非法字符的条目；保留 punycode。
- 去重 + 排序，输出确定性（内容不变则无差异）。
- `domain_regex` 无法用纯文本表达 → 单独存 `regex-*.txt`，不计入 `.lst`。

## 守卫

- `cn.lst` 行数 `< min_lines`（默认 10000）→ 中止不发布。
- 行数 `< 上次 count * ratio_guard`（默认 0.5）→ 中止（防上游改版/抓取失败）。

## 本地运行

```sh
python convert.py --out-dir dist --sources sources.json
```

## 许可 / 来源

- 数据来自 [flyzstu/sing-box-rules](https://github.com/flyzstu/sing-box-rules)，
  其 geosite 数据衍生自 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。
- 本项目仅做格式转换，遵循上游许可；请遵循上游仓库的许可与使用条款。
