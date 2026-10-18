"""Passive checks. Each check returns a dict: {name, status, detail, data}.

Status values: PASS, WARN, PARTIAL, FAIL, SKIP. Every check is a plain GET/HEAD or a
TLS handshake: no load testing, no fuzzing, no authentication.
"""
from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser

USER_AGENT = "sitecheck/0.1 (+passive checker; https://github.com/leighsrodney-prog/site-checker)"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def result(name, status, detail, **data):
    return {"name": name, "status": status, "detail": detail, "data": data}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, timeout=10.0, follow=True, method="GET", max_bytes=2_000_000):
    """Return (status, headers(dict, lower-case), body bytes, elapsed seconds, final url)."""
    handlers = [] if follow else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    t0 = time.perf_counter()
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:  # 4xx/5xx and unfollowed 3xx
        body = e.read(max_bytes) if method == "GET" else b""
        return e.code, {k.lower(): v for k, v in e.headers.items()}, body, time.perf_counter() - t0, url
    with resp:
        body = resp.read(max_bytes) if method == "GET" else b""
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, hdrs, body, time.perf_counter() - t0, resp.geturl()


def check_http(url, timeout=10.0, slow_ms=1500):
    try:
        status, headers, body, elapsed, final = fetch(url, timeout)
    except Exception as e:  # noqa: BLE001 - report, don't crash
        return result("http", "FAIL", f"Request failed: {e}"), None
    ms = round(elapsed * 1000)
    if status >= 400:
        st, msg = "FAIL", f"HTTP {status} in {ms} ms"
    elif ms > slow_ms:
        st, msg = "WARN", f"HTTP {status}, but slow: {ms} ms (threshold {slow_ms} ms, single sample)"
    else:
        st, msg = "PASS", f"HTTP {status} in {ms} ms (single sample)"
    return result("http", st, msg, status_code=status, response_ms=ms, final_url=final), (headers, body, final)


def evaluate_headers(headers):
    """Grade the 6 security headers. Report-only CSP counts as PARTIAL, not PASS."""
    rows, present = {}, 0
    for h in SECURITY_HEADERS:
        if h in headers:
            rows[h] = "PASS"
            present += 1
        elif h == "content-security-policy" and "content-security-policy-report-only" in headers:
            rows[h] = "PARTIAL"
        else:
            rows[h] = "FAIL"
    vals = set(rows.values())
    if vals == {"PASS"}:
        st = "PASS"
    elif present == 0 and "PARTIAL" not in vals:
        st = "FAIL"
    else:
        st = "PARTIAL"
    partial = [h for h, v in rows.items() if v == "PARTIAL"]
    msg = f"{present}/6 security headers enforced"
    if partial:
        msg += "; CSP is report-only (monitors but does not block)"
    return result("security_headers", st, msg, headers=rows)


def check_redirect(url, timeout=10.0):
    p = urllib.parse.urlsplit(url)
    http_url = urllib.parse.urlunsplit(("http", p.netloc, p.path or "/", p.query, ""))
    try:
        status, headers, _, _, _ = fetch(http_url, timeout, follow=False, method="GET", max_bytes=0)
    except Exception as e:  # noqa: BLE001
        return result("https_redirect", "WARN", f"Could not reach plain HTTP: {e}")
    loc = headers.get("location", "")
    if status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        st = "PASS" if status in (301, 308) else "WARN"
        msg = f"http:// redirects to https ({status})" + ("" if st == "PASS" else "; temporary redirect, permanent (301/308) preferred")
        return result("https_redirect", st, msg, status_code=status, location=loc)
    return result("https_redirect", "FAIL", f"http:// did not redirect to https (HTTP {status})", status_code=status, location=loc)


def cert_days_left(not_after: str, now: datetime | None = None) -> int:
    exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return (exp - now).days


def grade_cert(days, warn_days=21):
    if days < 0:
        return "FAIL", f"Certificate expired {-days} days ago"
    if days < warn_days:
        return "WARN", f"Certificate expires in {days} days"
    return "PASS", f"Certificate valid for {days} more days"


def check_tls(url, timeout=10.0, warn_days=21):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https":
        return result("tls", "SKIP", "URL is not https; TLS not checked")
    host, port = p.hostname, p.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return result("tls", "FAIL", f"Certificate did not verify: {e.verify_message}")
    except Exception as e:  # noqa: BLE001
        return result("tls", "FAIL", f"TLS handshake failed: {e}")
    days = cert_days_left(cert["notAfter"])
    st, msg = grade_cert(days, warn_days)
    return result("tls", st, msg, not_after=cert["notAfter"], days_left=days)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        ref = a.get("href") if tag in ("a", "link") else a.get("src") if tag in ("img", "script") else None
        if ref:
            self.links.append(ref)


def extract_links(html: str, base: str) -> list[str]:
    p = _LinkParser()
    p.feed(html)
    out, seen = [], set()
    for ref in p.links:
        ref = ref.strip()
        if ref.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absu = urllib.parse.urldefrag(urllib.parse.urljoin(base, ref))[0]
        if urllib.parse.urlsplit(absu).scheme in ("http", "https") and absu not in seen:
            seen.add(absu)
            out.append(absu)
    return out


def check_links(body: bytes, base: str, max_links=50, timeout=8.0, delay=0.1):
    links = extract_links(body.decode("utf-8", "replace"), base)
    checked, broken = links[:max_links], []
    for u in checked:
        try:
            status = fetch(u, timeout, method="HEAD")[0]
            if status in (405, 501):  # HEAD not supported; fall back to small GET
                status = fetch(u, timeout, max_bytes=1024)[0]
        except Exception as e:  # noqa: BLE001
            status = f"error: {type(e).__name__}"
        if not isinstance(status, int) or status >= 400:
            broken.append({"url": u, "status": status})
        time.sleep(delay)
    skipped = len(links) - len(checked)
    msg = f"{len(broken)} broken of {len(checked)} links checked on this page"
    if skipped:
        msg += f" ({skipped} more not checked, cap {max_links})"
    st = "PASS" if not broken else ("WARN" if len(broken) <= 2 else "FAIL")
    return result("broken_links", st, msg, checked=len(checked), found=len(links), broken=broken)


def check_lighthouse(url, timeout=180):
    exe = shutil.which("lighthouse")
    if not exe:
        return result("lighthouse", "SKIP", "Lighthouse CLI not installed; skipped")
    with tempfile.TemporaryDirectory() as d:
        out = f"{d}/lh.json"
        cmd = [exe, url, "--quiet", "--output=json", f"--output-path={out}",
               "--chrome-flags=--headless=new"]
        try:
            subprocess.run(cmd, check=True, timeout=timeout, capture_output=True)
            data = json.load(open(out))
        except Exception as e:  # noqa: BLE001
            return result("lighthouse", "SKIP", f"Lighthouse did not complete: {type(e).__name__}")
    scores = {k: round((v.get("score") or 0) * 100) for k, v in data.get("categories", {}).items()}
    low = min(scores.values()) if scores else 0
    st = "PASS" if low >= 90 else "WARN" if low >= 50 else "FAIL"
    return result("lighthouse", st, "Lab scores from one run (they vary between runs): " +
                  ", ".join(f"{k} {v}" for k, v in scores.items()), scores=scores)


def run_all(url, max_links=50, lighthouse=False, timeout=10.0, skip_redirect=False, skip_tls=False):
    if "://" not in url:
        url = "https://" + url
    checks = []
    http_res, page = check_http(url, timeout)
    checks.append(http_res)
    if not skip_tls:
        checks.append(check_tls(url, timeout))
    if page:
        headers, body, final = page
        checks.append(evaluate_headers(headers))
        if max_links > 0:
            checks.append(check_links(body, final, max_links, timeout))
    if not skip_redirect:
        checks.append(check_redirect(url, timeout))
    if lighthouse:
        checks.append(check_lighthouse(url))
    return {
        "tool": "sitecheck",
        "url": url,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarize(checks),
        "checks": checks,
    }


def summarize(checks):
    s = {k: 0 for k in ("PASS", "WARN", "PARTIAL", "FAIL", "SKIP")}
    for c in checks:
        s[c["status"]] = s.get(c["status"], 0) + 1
    return s
