from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import checks, report


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sitecheck", description="Passive website checker. Only check sites you own or have permission to test.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="check one URL")
    r.add_argument("url")
    r.add_argument("--out", default="reports", help="output directory")
    r.add_argument("--name", default="run", help="base filename for JSON/HTML")
    r.add_argument("--max-links", type=int, default=50, help="cap on links checked (0 disables)")
    r.add_argument("--timeout", type=float, default=10.0)
    r.add_argument("--lighthouse", action="store_true", help="run Lighthouse CLI if installed")
    r.add_argument("--fail-on", choices=["FAIL", "WARN", "never"], default="never", help="exit 1 if any check is at or below this")
    c = sub.add_parser("compare", help="before/after HTML from two JSON runs")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument("--out", default="reports/compare.html")
    c.add_argument("--label", default="")
    h = sub.add_parser("html", help="render HTML from one JSON run")
    h.add_argument("json")
    h.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    if a.cmd == "run":
        res = checks.run_all(a.url, max_links=a.max_links, lighthouse=a.lighthouse, timeout=a.timeout)
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{a.name}.json").write_text(json.dumps(res, indent=2))
        (out / f"{a.name}.html").write_text(report.render_single(res))
        for ch in res["checks"]:
            print(f"{ch['status']:8} {ch['name']:18} {ch['detail']}")
        print(f"wrote {out / a.name}.json and .html")
        bad = {"FAIL": {"FAIL"}, "WARN": {"FAIL", "WARN", "PARTIAL"}, "never": set()}[a.fail_on]
        return 1 if any(ch["status"] in bad for ch in res["checks"]) else 0
    if a.cmd == "compare":
        b, af = (json.loads(Path(p).read_text()) for p in (a.before, a.after))
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(report.render_compare(b, af, a.label))
        print(f"wrote {a.out}")
        return 0
    if a.cmd == "html":
        res = json.loads(Path(a.json).read_text())
        out = a.out or str(Path(a.json).with_suffix(".html"))
        Path(out).write_text(report.render_single(res))
        print(f"wrote {out}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
