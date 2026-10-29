# cloudnproxy 节点自动解析

用一百多个公共 DNS 服务器分别去查 `cloudnproxy.n.shifen.com` 的 A 记录，
把结果按 **GEO 地区 + 运营商** 归并，每个地区/运营商只留第一个 IP，
探测存活后输出成可以直接用的节点清单。

GitHub Actions 每 6 小时自动跑一次，结果提交回 `output/`。

## 为什么要用一堆 DNS

不同 DNS 服务器返回的 A 记录**子集不一样**——它们各自按自己的位置做 CDN 调度：

| DNS | 返回的 A 记录 |
|---|---|
| `114.114.114.114`（联通） | 只有 `110.242.70.68` / `.69` |
| `119.29.29.29`（腾讯） | 只有 `110.242.70.68` / `.69` |
| `168.95.192.1`（台湾中华电信） | 只有 `180.101.50.208` / `.249` |
| `8.8.8.8` / `1.1.1.1` | 全部 14 条 |

所以必须把 DNS 列表跑遍，才能把全国的边缘节点都挖出来。

同一个「地区+运营商」下有多个 DNS 时只查**首个**（`--no-dedupe` 可关掉），
实测 A 记录覆盖不变，但查询数从 326 降到 125、耗时从 27 秒降到 12 秒。

## 目录

```
baidu-direct/
├── .github/workflows/resolve.yml   # 定时任务
├── scripts/
│   ├── resolve.py                  # 核心脚本
│   └── probe.py                    # 单独探测节点存活
├── data/
│   ├── dns.txt                     # DNS 服务器列表（维基百科粘贴稿，脚本会解析）
│   └── srss/geosite-cn.srs         # 给生成的 sing-box 配置用的规则集
└── output/                         # 生成物（Action 会自动提交）
    ├── nodes.json                  # 完整数据
    ├── nodes.md                    # 人看的表格（含存活标记）
    ├── singbox-outbounds.json      # sing-box 出站数组
    ├── singbox-config.json         # 完整可跑的 sing-box 配置
    └── clash-proxies.yaml          # Clash 代理节点
```

## 输出

`output/nodes.md`：

| # | 地区 | 运营商 | 节点 IP | 存活 | 同组其他 IP |
|---|------|--------|---------|------|-------------|
| 1 | 河北省 承德市 | China Unicom Hebei Province Network | `110.242.70.68` | ✅ | `110.242.70.69` |
| 6 | 江苏 南京 | China Telecom (Chinanet JS) | `180.101.50.208` | ✅ | `180.101.50.249` |

`output/singbox-config.json` 直接能跑（自带 inbound / DNS / 选择组 / 路由），
出站**已经带好百度直连要的 header**：

```json
{
  "type": "http",
  "tag": "baidu-江苏-南京-China-Telecom-Chinanet-JS",
  "server": "180.101.50.208",
  "server_port": 443,
  "headers": {
    "Host": ["ascdn.baidu.com"],
    "X-T5-Auth": ["1951164069"],
    "User-Agent": ["okhttp/3.11.0 SP-engine/2.71.0 Dalvik/2.1.0 ... baiduboxapp/13.33.0.11 (Baidu; P1 9)"]
  }
}
```

## 本地跑

```bash
pip install dnspython requests
python scripts/resolve.py --domain cloudnproxy.n.shifen.com --dns data/dns.txt --out output
```

参数：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--domain` | `cloudnproxy.n.shifen.com` | 要解析的域名 |
| `--dns` | `data/dns.txt` | DNS 列表文件 |
| `--out` | `output` | 输出目录 |
| `--timeout` | `3.0` | 单次 DNS 查询超时（秒） |
| `--workers` | `32` | 并发查询线程数 |
| `--no-dedupe` | 关 | 每个「地区+运营商」查全部 DNS，而不是只查首个 |
| `--no-probe` | 关 | 不探测节点存活 |
| `--probe-target` | `www.baidu.com` | 探测用的目标域名 |

单独探测：

```bash
python scripts/probe.py output/nodes.json www.baidu.com
```

## 开启 GitHub Actions

1. 新建一个空仓库，把这个目录推上去。
2. 仓库 Settings → Actions → General → Workflow permissions 选 **Read and write permissions**。
3. 第一次手动触发：**Actions → Resolve cloudnproxy nodes → Run workflow**。
4. 之后每 6 小时自动跑，结果自动提交到 `output/`。

## 注意

- DNS 列表里的 IPv6 全部跳过，只取 A 记录。
- 同一个「地区 + 运营商」下有多个 IP 时只保留第一个，其余记在 `extra_ips`。
- 节点存活探测就是真发一次带 header 的 CONNECT，403/503 的节点不会进 `singbox-*.json`。
- 百度边缘节点的 Host 校验策略会变（`ascdn.baidu.com` / `cloudnproxy.baidu.com:443` / 不带 Host 轮换），
  万一全站 403 或 503，把 `scripts/resolve.py` 顶部的 `BAIDU_HOST_HEADER` 换掉重跑。
- GEO 定位走 `ip-api.com` 批量接口（`lang=zh-CN`），失败自动退回 `ipwho.is`。
- 从美国 runner 跑也能覆盖：国际 DNS（8.8.8.8 / 1.1.1.1 / 9.9.9.9 / OpenDNS）都返回全量 14 条。
