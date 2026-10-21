# site-checker

[![CI](https://github.com/leighsrodney-prog/site-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/leighsrodney-prog/site-checker/actions/workflows/ci.yml)

📄 **[Sample before/after report (sample data)](examples/sample-compare.html)**

A small, dependency-free **passive website checker**. Give it a URL and it checks uptime, response
time, TLS expiry, security headers, the http-to-https redirect and broken links, then writes **JSON plus
a static HTML report**. Two JSON runs can be rendered as a **before/after comparison** page.

> Only check sites you own or have permission to test. The tool is passive: a few ordinary GET/HEAD
> requests and one TLS handshake. It does **no load testing, no fuzzing and no login**.

## Motivation
Website QA is test engineering too: repeatable checks, clear pass/fail criteria, and reports that say
what was actually measured. We built this to show fixes (before/after) on our own site, capitaleyemotors.com, tested with
permission, without overstating what a passive scan can prove.

## Design
```
sitecheck run URL
  checks.py   http (status, response time)   tls (cert expiry)
              security_headers (6)           https_redirect
              broken_links (one page, capped) lighthouse (optional CLI)
        |
  reports/<name>.json  ->  report.py  ->  reports/<name>.html
sitecheck compare before.json after.json  ->  before/after HTML
```
| Check | PASS | WARN | PARTIAL | FAIL |
|---|---|---|---|---|
| http | 2xx/3xx under 1500 ms | slow (single sample) | | 4xx/5xx or unreachable |
| tls | ≥ 21 days left | < 21 days left | | expired / does not verify |
| security_headers | all 6 enforced | | some present, or CSP report-only | none |
| https_redirect | 301/308 to https | 302/307 to https | | no redirect |
| broken_links | 0 broken | 1–2 broken | | 3+ broken |
| lighthouse | all categories ≥ 90 | ≥ 50 | | < 50 |

Headers checked: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. A `Content-Security-Policy-Report-Only`
header counts as **PARTIAL**: it monitors violations but blocks nothing. Lighthouse is skipped
(SKIP) unless the `lighthouse` CLI is installed and `--lighthouse` is passed.

## Usage
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt          # only pytest; the tool itself is stdlib-only
python3 -m sitecheck run https://example.com --out reports --name before --max-links 25
# ...deploy fixes, then:
python3 -m sitecheck run https://example.com --out reports --name after --max-links 25
python3 -m sitecheck compare reports/before.json reports/after.json --out reports/compare.html
python3 -m sitecheck run https://example.com --fail-on FAIL   # exit 1 on any FAIL (CI gate)
pytest -q                                # local mock server only; external network blocked
```
Example console output:
```
PASS     http               HTTP 200 in 212 ms (single sample)
PASS     tls                Certificate valid for 85 more days
PARTIAL  security_headers   5/6 security headers enforced; CSP is report-only (monitors but does not block)
PASS     broken_links       0 broken of 18 links checked on this page
PASS     https_redirect     http:// redirects to https (301)
```

## Sample report
`examples/` holds **clearly labeled sample data** (JSON marked `"sample": true`, which makes every generated HTML page show a SAMPLE DATA banner) for example.com (illustrative values, not a real
scan) and the HTML it produces. Note the after run is still PARTIAL on headers: the CSP is
report-only, and the report says so instead of calling it a pass.

## Limits (honest wording)
- One page, one sample. Response time and Lighthouse scores vary between runs.
- A PASS means the check found nothing wrong, not that the site is "secure".
- Header checks look for presence, not policy quality.

## Authorship

Built with AI coding assistance. I defined the requirements, ran the tests, and reviewed the changes.

## License

MIT. See [LICENSE](LICENSE).
