#!/usr/bin/env python3
"""校验 output/v2rayn-links.txt 里的链接是否满足 v2rayN InnerFmt.ResolveSingle 的要求。

v2rayN 的解析逻辑（ServiceLib/Handler/Fmt/InnerFmt.cs）：
  - 必须以 v2rayn:// 开头
  - base64url 解码后是 ProfileItem 的 JSON
  - ConfigVersion 必须 == 4
  - ConfigType 必须是已定义的枚举值（Outbound = 13）
  - CoreType 只能是 null / Xray(2) / sing_box(24)
  - ConfigType == Outbound 时，必须带 CustomOutboundObj（否则拒绝导入）
"""
import base64
import json
import sys

PREFIX = "v2rayn://outbound/"
VALID_CORE = {None, 2, 24}


def decode(link: str):
    raw = link.strip()
    if not raw.startswith(PREFIX):
        raise ValueError("协议头不对")
    b64 = raw[len(PREFIX):]
    b64 += "=" * (-len(b64) % 4)
    return json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "output/v2rayn-links.txt"
    lines = [l for l in open(path, encoding="utf-8").read().splitlines() if l.strip()]
    bad = 0
    for i, link in enumerate(lines, 1):
        try:
            p = decode(link)
            errs = []
            if p.get("ConfigVersion") != 4:
                errs.append(f"ConfigVersion={p.get('ConfigVersion')}")
            if p.get("ConfigType") != 13:
                errs.append(f"ConfigType={p.get('ConfigType')}")
            if p.get("CoreType") not in VALID_CORE:
                errs.append(f"CoreType={p.get('CoreType')}")
            co = p.get("CustomOutboundObj")
            if not isinstance(co, dict):
                errs.append("缺 CustomOutboundObj")
            else:
                if co.get("type") != "http":
                    errs.append(f"type={co.get('type')}")
                if not co.get("server"):
                    errs.append("缺 server")
                h = co.get("headers") or {}
                for k in ("Host", "X-T5-Auth", "User-Agent"):
                    if k not in h:
                        errs.append(f"缺 header {k}")
            if errs:
                bad += 1
                print(f"[{i:2d}] FAIL {p.get('Remarks','?')}  -> {'; '.join(errs)}")
            else:
                print(
                    f"[{i:2d}] OK   {p.get('Remarks','?'):<46} "
                    f"{co['server']}:{co['server_port']}  Host={co['headers']['Host'][0]}"
                )
        except Exception as exc:  # noqa: BLE001
            bad += 1
            print(f"[{i:2d}] FAIL 解码失败: {exc}")
    print(f"\n共 {len(lines)} 条，{len(lines) - bad} 条通过，{bad} 条失败")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
