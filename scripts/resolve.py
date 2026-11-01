#!/usr/bin/env python3
"""
cloudnproxy 节点自动解析器

流程:
    1. 解析 DNS 列表(dns.txt, 维基百科粘贴稿, 含 IPv6 / 跨行续行 / 名称换行)
    2. 用列表里每个 DNS 服务器分别查询域名的 A 记录(只取 IPv4)
    3. 汇总所有 A 记录, 去重
    4. 对每个 IP 做 GEO 定位(省 / 市 / 运营商)
    5. 按「地区 + 运营商」分组, 每组只保留第一个 IP
    6. 输出节点清单(json / markdown / sing-box outbounds / clash proxies)

用法:
    python scripts/resolve.py --domain cloudnproxy.n.shifen.com \
        --dns data/dns.txt --out output
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import hashlib
import json
import os
import re
import socket
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone, timedelta

try:
    import dns.resolver
    import dns.exception
except ImportError:  # pragma: no cover
    sys.exit("缺少依赖: pip install dnspython")

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("缺少依赖: pip install requests")

CST = timezone(timedelta(hours=8))

IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]*:[0-9a-fA-F:]*$")
HEADER_RE = re.compile(r"^(名称|DNS服务器|.*地址.*大全)$")

# 百度直连代理需要的请求头
BAIDU_HOST_HEADER = "ascdn.baidu.com"
BAIDU_AUTH = "1951164069"
BAIDU_UA = (
    "okhttp/3.11.0 SP-engine/2.71.0 Dalvik/2.1.0 (Linux; U; Android 9; "
    "HMA-AL00 Build/PQ3B.190801.002) baiduboxapp/13.33.0.11 (Baidu; P1 9)"
)


# ---------------------------------------------------------------- dns.txt 解析


def is_ipv4(tok: str) -> bool:
    m = IPV4_RE.match(tok)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def is_ipv6(tok: str) -> bool:
    return ":" in tok and not is_ipv4(tok) and bool(IPV6_RE.match(tok))


def group_key(name: str) -> str:
    """条目归组键：去掉结尾的 DNS，作为「地区+运营商」的标识。

    例：'北京移动DNS' -> '北京移动'，'114DNS' -> '114'，'DNS 派 联通' -> 'DNS 派 联通'
    """
    key = name.strip()
    if key.endswith("DNS"):
        key = key[:-3].strip()
    return key or name.strip()


def parse_dns_file(path: str, dedupe: bool = True):
    """把 dns.txt 解析成 [(名称, [ipv4, ...]), ...]，忽略 IPv6。

    dedupe=True 时，同一个「地区+运营商」分组里的多个 DNS 只保留首个。
    """
    entries: list[tuple[str, list[str]]] = []
    cur_name = ""
    cur_ips: list[str] = []

    def flush():
        nonlocal cur_name, cur_ips
        if cur_ips:
            entries.append((cur_name or "未命名", cur_ips))
        cur_name, cur_ips = "", []

    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            # tab 或 2 个以上空格分列；名称里可能有空格，所以优先按 tab 切
            if "\t" in line:
                cells = [c.strip() for c in line.split("\t") if c.strip()]
            else:
                cells = [c.strip() for c in re.split(r"\s{2,}", line) if c.strip()]

            ips = [c for c in cells if is_ipv4(c)]
            names = [c for c in cells if not is_ipv4(c) and not is_ipv6(c)]

            if names and not ips:
                # 纯名称行：可能是章节标题，也可能是名称换行的表格
                name = " ".join(names)
                if HEADER_RE.match(name) or name.endswith("地址") or name.endswith("大全"):
                    flush()
                    continue
                if cur_ips:
                    flush()
                cur_name = name
                continue

            if names and ips:
                flush()
                cur_name = " ".join(names)
                cur_ips = list(ips)
                continue

            # 只有 IP：上一条的续行
            if ips:
                if not cur_name:
                    cur_name = "未命名"
                cur_ips.extend(ips)

    flush()

    # dedupe: 同一个「地区+运营商」分组只保留首个 DNS 服务器
    if dedupe:
        kept_groups: set[str] = set()
        deduped: list[tuple[str, list[str]]] = []
        for name, ips in entries:
            gk = group_key(name)
            if gk in kept_groups:
                continue
            kept_groups.add(gk)
            # 组内多个 DNS 只用首个
            deduped.append((name, ips[:1]))
        entries = deduped

    # 同一个 IP 只保留一次，但保留它属于哪些条目
    seen: dict[str, list[str]] = OrderedDict()
    for name, ips in entries:
        for ip in ips:
            seen.setdefault(ip, [])
            if name not in seen[ip]:
                seen[ip].append(name)

    return [(ip, names) for ip, names in seen.items()]


# ---------------------------------------------------------------- DNS 查询


def query_one(server_ip: str, domain: str, timeout: float):
    """用指定 DNS 服务器查 A 记录。返回 (ip_list, cname, elapsed_ms, error)"""
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [server_ip]
    res.timeout = timeout
    res.lifetime = timeout
    t0 = time.time()
    try:
        ans = res.resolve(domain, "A", raise_on_no_answer=False)
        elapsed = int((time.time() - t0) * 1000)
        if ans.rrset is None:
            return [], "", elapsed, "无 A 记录"
        ips = sorted({r.address for r in ans.rrset})
        cname = str(ans.canonical_name) if ans.canonical_name else ""
        return ips, cname, elapsed, ""
    except dns.exception.Timeout:
        return [], "", int((time.time() - t0) * 1000), "超时"
    except Exception as exc:  # noqa: BLE001
        return [], "", int((time.time() - t0) * 1000), f"{type(exc).__name__}: {exc}"


def query_all(servers, domain: str, timeout: float, workers: int):
    results = []
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        fut_map = {pool.submit(query_one, ip, domain, timeout): ip for ip in servers}
        for fut in futures.as_completed(fut_map):
            ip = fut_map[fut]
            ips, cname, elapsed, err = fut.result()
            results.append(
                {
                    "dns": ip,
                    "ok": bool(ips),
                    "ips": ips,
                    "cname": cname,
                    "ms": elapsed,
                    "error": err,
                }
            )
    results.sort(key=lambda r: r["dns"])
    return results


# ---------------------------------------------------------------- GEO 定位


def geo_batch(ips: list[str]) -> dict[str, dict]:
    """ip-api.com 批量定位；失败则退回 ipwho.is 逐个查。"""
    info: dict[str, dict] = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i : i + 100]
        try:
            r = requests.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "lang": "zh-CN"} for ip in chunk],
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            r.raise_for_status()
            for row in r.json():
                if row.get("status") == "success":
                    info[row["query"]] = row
                else:
                    info[row["query"]] = {"status": "fail", "message": row.get("message", "")}
        except Exception as exc:  # noqa: BLE001
            print(f"  ! ip-api 批量失败({exc})，改用 ipwho.is")
            break

    missing = [ip for ip in ips if ip not in info or info[ip].get("status") != "success"]
    for ip in missing:
        try:
            r = requests.get(f"https://ipwho.is/{ip}?lang=zh-CN", timeout=20)
            d = r.json()
            if d.get("success"):
                info[ip] = {
                    "status": "success",
                    "country": d.get("country", ""),
                    "regionName": d.get("region", ""),
                    "city": d.get("city", ""),
                    "isp": d.get("connection", {}).get("isp", ""),
                    "org": d.get("connection", {}).get("org", ""),
                    "as": d.get("connection", {}).get("asn", 0),
                }
            else:
                info[ip] = {"status": "fail", "message": d.get("message", "")}
        except Exception:  # noqa: BLE001
            info[ip] = {"status": "fail", "message": "查询失败"}

    return info


def region_of(row: dict) -> str:
    """把省 + 市压成一个地区标签。"""
    parts = [row.get("regionName") or "", row.get("city") or ""]
    parts = [p for p in parts if p and p not in ("-", "None")]
    seen = []
    for p in parts:
        if p not in seen:
            seen.append(p)
    return " ".join(seen) if seen else "未知地区"


def isp_of(row: dict) -> str:
    isp = (row.get("isp") or "").strip()
    org = (row.get("org") or "").strip()
    if isp and org and org not in isp:
        return f"{isp} ({org})"
    return isp or org or "未知运营商"


# ---------------------------------------------------------------- 输出


def build_nodes(records, geo):
    """按「地区 + 运营商」分组，每组保留第一个 IP。"""
    groups: OrderedDict[tuple[str, str], dict] = OrderedDict()
    for rec in records:
        ip = rec["ip"]
        g = geo.get(ip, {})
        region = region_of(g) if g.get("status") == "success" else "未知地区"
        isp = isp_of(g) if g.get("status") == "success" else "未知运营商"
        key = (region, isp)
        if key in groups:
            groups[key]["extra_ips"].append(ip)
            groups[key]["dns_servers"].extend(rec["dns"])
            continue
        groups[key] = {
            "region": region,
            "isp": isp,
            "ip": ip,
            "extra_ips": [],
            "dns_servers": list(rec["dns"]),
            "asn": g.get("as", "") if g.get("status") == "success" else "",
            "country": g.get("country", "") if g.get("status") == "success" else "",
        }
    return list(groups.values())


def v2rayn_link(outbound: dict, remarks: str) -> str:
    """生成 v2rayN 的 v2rayn://outbound/<base64url> 分享链接。

    v2rayN 用它自己的 InnerFmt 解析：
      payload = ProfileItem 序列化结果，其中 CustomOutboundObj 装 outbound 本体
      ConfigType = 13 (Outbound)、ConfigVersion = 4、CoreType = 24 (sing_box)
      base64url 编码（无 padding）
    """
    payload = {
        "IndexId": f"baidu-{hashlib.md5(remarks.encode('utf-8')).hexdigest()[:12]}",
        "ConfigType": 13,
        "ConfigVersion": 4,
        "CoreType": 24,
        "Remarks": remarks,
        "CustomOutboundObj": outbound,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    b64 = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    return f"v2rayn://outbound/{b64}"


def dns_label(dns_ip: str, name_map: dict[str, list[str]]) -> str:
    names = name_map.get(dns_ip) or []
    if names:
        return f"{'/'.join(names[:2])} ({dns_ip})"
    return dns_ip


def probe_node(ip: str, target: str = "www.baidu.com", port: int = 443, timeout: float = 6.0) -> tuple[bool, str]:
    """对节点 IP 发一次带 header 的 CONNECT，看隧道能不能建起来。"""
    req = (
        f"CONNECT {target}:{port} HTTP/1.1\r\n"
        f"Host: {BAIDU_HOST_HEADER}\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        f"X-T5-Auth: {BAIDU_AUTH}\r\n"
        f"User-Agent: {BAIDU_UA}\r\n\r\n"
    )
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req.encode("latin-1"))
            head = s.recv(256).decode("latin-1", "replace").split("\r\n")[0]
            return (" 200 " in head), head
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}"


def write_outputs(outdir: str, domain: str, dns_results, records, geo, nodes, name_map=None):
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now(CST)

    payload = {
        "domain": domain,
        "generated_at": stamp.isoformat(),
        "dns_total": len(dns_results),
        "dns_ok": sum(1 for r in dns_results if r["ok"]),
        "unique_a_records": len(records),
        "nodes": nodes,
        "a_records": [
            {
                "ip": r["ip"],
                "region": region_of(geo.get(r["ip"], {}))
                if geo.get(r["ip"], {}).get("status") == "success"
                else "",
                "isp": isp_of(geo.get(r["ip"], {}))
                if geo.get(r["ip"], {}).get("status") == "success"
                else "",
                "dns_servers": r["dns"],
            }
            for r in records
        ],
        "dns_results": dns_results,
    }

    with open(os.path.join(outdir, "nodes.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)

    # sing-box outbounds：直接能用，带百度直连的 header（只输出探测通过的）
    outbounds = []
    links = []
    for i, n in enumerate(nodes):
        if n.get("alive") is False:
            continue
        raw = f"baidu-{n['region']}-{n['isp']}"
        tag = re.sub(r"[^\w\u4e00-\u9fff-]+", "-", raw, flags=re.UNICODE).strip("-")
        tag = tag[:60]
        body = {
            "type": "http",
            "server": n["ip"],
            "server_port": 443,
            "headers": {
                "Host": [BAIDU_HOST_HEADER],
                "X-T5-Auth": [BAIDU_AUTH],
                "User-Agent": [BAIDU_UA],
            },
        }
        outbounds.append({"type": "http", "tag": tag, **body})
        # v2rayN 的「自定义远端站」：tag 由 v2rayN 自己填，这里不带
        links.append(v2rayn_link(body, f"百度直连 {n['region']} {n['isp']}"))
    with open(os.path.join(outdir, "singbox-outbounds.json"), "w", encoding="utf-8") as fh:
        json.dump(outbounds, fh, ensure_ascii=False, indent=2)

    # v2rayN 分享链接：一行一个，直接全选复制进 v2rayN 批量导入
    with open(os.path.join(outdir, "v2rayn-links.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(links) + ("\n" if links else ""))

    # 完整可跑的 sing-box 配置：自带 inbound / DNS / 选择组 / 路由
    srss = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "srss")
    full = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "local", "type": "udp", "server": "223.5.5.5"},
                {"tag": "remote", "type": "tcp", "server": "8.8.8.8", "detour": "proxy"},
            ],
            "rules": [{"rule_set": ["geosite-cn"], "server": "local"}],
            "final": "remote",
        },
        "inbounds": [
            {"type": "mixed", "tag": "socks", "listen": "127.0.0.1", "listen_port": 10808}
        ],
        "outbounds": outbounds
        + [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": [o["tag"] for o in outbounds] or ["direct"],
                "default": outbounds[0]["tag"] if outbounds else "direct",
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"outbound": "direct", "ip_is_private": True},
            ],
            "rule_set": [
                {
                    "tag": "geosite-cn",
                    "type": "local",
                    "format": "binary",
                    "path": os.path.join(srss, "geosite-cn.srs"),
                }
            ],
            "default_domain_resolver": {"server": "local"},
            "final": "proxy",
        },
    }
    with open(os.path.join(outdir, "singbox-config.json"), "w", encoding="utf-8") as fh:
        json.dump(full, fh, ensure_ascii=False, indent=2)

    # clash proxies
    lines = ["proxies:"]
    for n in nodes:
        if n.get("alive") is False:
            continue
        name = f"{n['region']} {n['isp']}".strip()
        lines += [
            f"  - name: \"{name}\"",
            "    type: http",
            f"    server: {n['ip']}",
            "    port: 443",
            "    headers:",
            f"      Host: \"{BAIDU_HOST_HEADER}\"",
            f"      X-T5-Auth: \"{BAIDU_AUTH}\"",
            f"      User-Agent: \"{BAIDU_UA}\"",
        ]
    with open(os.path.join(outdir, "clash-proxies.yaml"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # 完整可跑的 Clash / mihomo 配置
    cproxy_lines: list[str] = []
    cnames: list[str] = []
    for n in nodes:
        if n.get("alive") is False:
            continue
        name = f"{n['region']} {n['isp']}".strip()
        cnames.append(name)
        cproxy_lines += [
            f"  - name: \"{name}\"",
            "    type: http",
            f"    server: {n['ip']}",
            "    port: 443",
            "    headers:",
            f"      Host: \"{BAIDU_HOST_HEADER}\"",
            f"      X-T5-Auth: \"{BAIDU_AUTH}\"",
            f"      User-Agent: \"{BAIDU_UA}\"",
        ]
    group_members = [f'      - "{c}"' for c in cnames] or ["      - DIRECT"]
    clash = [
        "mixed-port: 2080",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "ipv6: false",
        "external-controller: 127.0.0.1:19090",
        "",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  enhanced-mode: redir-host",
        "  default-nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "  nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "",
        "proxies:",
        *cproxy_lines,
        "",
        "proxy-groups:",
        "  - name: PROXY",
        "    type: select",
        "    proxies:",
        *group_members,
        "",
        "rules:",
        "  - MATCH,PROXY",
        "",
    ]
    with open(os.path.join(outdir, "clash-config.yaml"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(clash))

    # markdown 表格
    alive_cnt = sum(1 for n in nodes if n.get("alive"))
    md = [
        f"# {domain} 节点清单",
        "",
        f"- 生成时间: {stamp.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"- DNS 服务器: {payload['dns_ok']}/{payload['dns_total']} 可用",
        f"- 唯一 A 记录: {len(records)} 条",
        f"- 按地区+运营商归并后节点: {len(nodes)} 个（探测可用 {alive_cnt} 个）",
        "",
        "| # | 地区 | 运营商 | 节点 IP | 存活 | ASN | 同组其他 IP | 解析来源 DNS |",
        "|---|------|--------|---------|------|-----|--------------|--------------|",
    ]
    for i, n in enumerate(nodes, 1):
        extra = "<br>".join(n["extra_ips"]) or "-"
        src_list = sorted(set(n["dns_servers"]))
        labels = [dns_label(s, name_map or {}) for s in src_list]
        srcs = "<br>".join(labels[:3])
        if len(labels) > 3:
            srcs += f"<br>…等 {len(labels)} 个"
        if not labels:
            srcs = "-"
        alive = n.get("alive")
        mark = "✅" if alive else ("❌" if alive is False else "-")
        md.append(
            f"| {i} | {n['region']} | {n['isp']} | `{n['ip']}` | {mark} | {n['asn']} | {extra} | {srcs} |"
        )
    md.append("")
    md.append("## v2rayN 分享链接")
    md.append("")
    md.append("一行一个，全选复制到 v2rayN「从剪贴板导入」即可。")
    md.append("")
    md.append("```")
    md.extend(links)
    md.append("```")
    md.append("")
    with open(os.path.join(outdir, "nodes.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default="cloudnproxy.n.shifen.com")
    ap.add_argument("--dns", default="data/dns.txt")
    ap.add_argument("--out", default="output")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument(
        "--no-dedupe",
        action="store_true",
        help="不去重：同一个「地区+运营商」下的所有 DNS 都查（默认每组只查首个）",
    )
    ap.add_argument(
        "--no-probe",
        action="store_true",
        help="不探测节点存活（默认每个节点发一次 CONNECT 验证）",
    )
    ap.add_argument("--probe-target", default="www.baidu.com", help="探测用的目标域名")
    args = ap.parse_args()

    print(f"[*] 解析 DNS 列表: {args.dns}")
    servers = parse_dns_file(args.dns, dedupe=not args.no_dedupe)
    name_map: dict[str, list[str]] = {}
    for ip, names in servers:
        name_map[ip] = names
    print(f"[*] 得到 {len(servers)} 个 IPv4 DNS 服务器" + ("（已按地区+运营商去重）" if not args.no_dedupe else "（未去重）"))

    print(f"[*] 查询 {args.domain} 的 A 记录 ...")
    dns_results = query_all([ip for ip, _ in servers], args.domain, args.timeout, args.workers)
    ok = sum(1 for r in dns_results if r["ok"])
    print(f"[*] {ok}/{len(dns_results)} 个 DNS 返回了 A 记录")

    # 汇总：哪个 DNS 返回了哪个 IP（保持发现顺序，方便「取首个」）
    ip_order: list[str] = []
    ip_sources: dict[str, list[str]] = {}
    for r in dns_results:
        for ip in r["ips"]:
            if ip not in ip_sources:
                ip_order.append(ip)
                ip_sources[ip] = []
            ip_sources[ip].append(r["dns"])

    records = [{"ip": ip, "dns": ip_sources[ip]} for ip in ip_order]
    print(f"[*] 去重后 {len(records)} 条 A 记录")

    print("[*] GEO 定位 ...")
    geo = geo_batch([r["ip"] for r in records])

    nodes = build_nodes(records, geo)
    print(f"[*] 按地区+运营商归并: {len(nodes)} 个节点")

    if not args.no_probe:
        print(f"[*] 探测节点存活 (CONNECT {args.probe_target}) ...")
        with futures.ThreadPoolExecutor(max_workers=8) as pool:
            fut_map = {pool.submit(probe_node, n["ip"], args.probe_target): n for n in nodes}
            for fut in futures.as_completed(fut_map):
                n = fut_map[fut]
                alive, status = fut.result()
                n["alive"] = alive
                n["probe_status"] = status
        for n in nodes:
            n.setdefault("alive", None)
        ok_cnt = sum(1 for n in nodes if n.get("alive"))
        print(f"[*] 探测通过 {ok_cnt}/{len(nodes)}")

    write_outputs(args.out, args.domain, dns_results, records, geo, nodes, name_map)

    print()
    for i, n in enumerate(nodes, 1):
        mark = "OK " if n.get("alive") else "   "
        print(f"  {mark}{i:2d}. {n['region']:<12} {n['isp']:<28} {n['ip']}")
    print(f"\n[*] 输出目录: {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
