import json
from datetime import datetime, timezone

from sitecheck import checks, report
from sitecheck.cli import main


def test_headers_report_only_csp_is_partial():
    h = {k: "x" for k in checks.SECURITY_HEADERS if k != "content-security-policy"}
    h["content-security-policy-report-only"] = "default-src 'self'"
    r = checks.evaluate_headers(h)
    assert r["status"] == "PARTIAL"
    assert r["data"]["headers"]["content-security-policy"] == "PARTIAL"
    assert "report-only" in r["detail"]


def test_headers_all_present_pass_and_none_fail():
    assert checks.evaluate_headers({k: "x" for k in checks.SECURITY_HEADERS})["status"] == "PASS"
    assert checks.evaluate_headers({})["status"] == "FAIL"


def test_cert_grading():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert checks.cert_days_left("Mar  1 00:00:00 2026 GMT", now) == 59
    assert checks.grade_cert(59)[0] == "PASS"
    assert checks.grade_cert(5)[0] == "WARN"
    assert checks.grade_cert(-1)[0] == "FAIL"


def test_tls_skipped_for_http():
    assert checks.check_tls("http://127.0.0.1/")["status"] == "SKIP"


def test_extract_links_dedupes_and_filters():
    html = '<a href="/a">a</a><a href="/a#x">a</a><a href="mailto:x@example.com">m</a><a href="#t">t</a><img src="i.png">'
    assert checks.extract_links(html, "https://example.com/p/") == ["https://example.com/a", "https://example.com/p/i.png"]


def test_http_ok_and_error(server):
    assert checks.check_http(server + "/")[0]["status"] == "PASS"
    assert checks.check_http(server + "/err")[0]["status"] == "FAIL"


def test_http_slow_is_warn(server):
    assert checks.check_http(server + "/ok", slow_ms=-1)[0]["status"] == "WARN"


def test_broken_links_with_cap(server):
    _, (h, body, final) = checks.check_http(server + "/")
    r = checks.check_links(body, final, max_links=10, delay=0)
    assert r["data"]["checked"] == 3
    assert [b["url"] for b in r["data"]["broken"]] == [server + "/missing"]
    assert r["status"] == "WARN"
    capped = checks.check_links(body, final, max_links=1, delay=0)
    assert capped["data"]["checked"] == 1 and "not checked" in capped["detail"]


def test_redirect(monkeypatch, server):
    # check_redirect rewrites to http://, which is what the local server speaks
    base = server.replace("http://", "https://")
    assert checks.check_redirect(base + "/redirect-perm")["status"] == "PASS"
    assert checks.check_redirect(base + "/redirect-temp")["status"] == "WARN"
    assert checks.check_redirect(base + "/ok")["status"] == "FAIL"


def test_external_network_blocked():
    r, _ = checks.check_http("http://example.com/", timeout=1)
    assert r["status"] == "FAIL"


def test_lighthouse_skips_when_missing(monkeypatch):
    monkeypatch.setattr(checks.shutil, "which", lambda _: None)
    assert checks.check_lighthouse("https://example.com")["status"] == "SKIP"


def test_cli_run_and_compare(server, tmp_path):
    rc = main(["run", server + "/", "--out", str(tmp_path), "--name", "before", "--max-links", "5"])
    assert rc == 0
    data = json.loads((tmp_path / "before.json").read_text())
    names = [c["name"] for c in data["checks"]]
    assert names[:2] == ["http", "tls"] and "security_headers" in names
    assert "<html" in (tmp_path / "before.html").read_text()
    assert main(["run", server + "/err", "--out", str(tmp_path), "--name", "e", "--fail-on", "FAIL"]) == 1
    after = dict(data, checks=[dict(c, status="PASS") for c in data["checks"]])
    (tmp_path / "after.json").write_text(json.dumps(after))
    out = tmp_path / "c.html"
    assert main(["compare", str(tmp_path / "before.json"), str(tmp_path / "after.json"), "--out", str(out)]) == 0
    assert "improved" in out.read_text()


def test_compare_and_escaping():
    b = {"url": "https://example.com", "checked_at": "t1", "summary": {"FAIL": 1},
         "checks": [{"name": "h", "status": "FAIL", "detail": "<script>"}]}
    a = dict(b, checked_at="t2", checks=[{"name": "h", "status": "PARTIAL", "detail": "x"}])
    assert report.compare(b, a)[0]["change"] == "improved"
    assert report.compare(a, b)[0]["change"] == "regressed"
    html = report.render_compare(b, a)
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_sample_banner_only_for_sample_runs():
    run = {"url": "https://example.com", "checked_at": "t", "summary": {}, "checks": []}
    assert report.SAMPLE_LABEL not in report.render_single(run)
    assert report.SAMPLE_LABEL in report.render_single(dict(run, sample=True))
    assert report.SAMPLE_LABEL in report.render_compare(run, dict(run, sample=True))
