#!/usr/bin/env python3
"""节点存活探测：对 output/nodes.json 里的每个 IP 发一次带 header 的 CONNECT。"""
import json
import socket
import sys

UA = ("okhttp/3.11.0 SP-engine/2.71.0 Dalvik/2.1.0 (Linux; U; Android 9; "
      "HMA-AL00 Build/PQ3B.190801.002) baiduboxapp/13.33.0.11 (Baidu; P1 9)")
HOST = "ascdn.baidu.com"
AUTH = "1951164069"


def probe(ip, target="www.baidu.com", port=443, timeout=6.0):
    req = (
        f"CONNECT {target}:{port} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        f"X-T5-Auth: {AUTH}\r\n"
        f"User-Agent: {UA}\r\n\r\n"
    )
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req.encode("latin-1"))
            head = s.recv(256).decode("latin-1", "replace").split("\r\n")[0]
            return head
    except Exception as exc:  # noqa: BLE001
        return f"ERR {type(exc).__name__}"


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "output/nodes.json"
    target = sys.argv[2] if len(sys.argv) > 2 else "www.baidu.com"
    data = json.load(open(path, encoding="utf-8"))
    for n in data["nodes"]:
        r = probe(n["ip"], target)
        flag = "OK " if " 200 " in r else "   "
        print(f'{flag}{n["region"]:<12} {n["isp"][:34]:<34} {n["ip"]:<16} {r}')
