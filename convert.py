#!/usr/bin/env python3
"""Convert flyzstu/sing-box-rules geosite (sing-box rule-set JSON) into
smartdns domain-set plain-text lists.

For each job in sources.json it emits into --out-dir:
  <name>.lst           one domain per line (sorted, deduped; smartdns suffix match)
  <name>.lst.sha256    "sha256  <name>.lst"
  regex-<name>.txt     domain_regex entries (reference only; smartdns has no regex
                       domain matching, these are NOT included in the .lst)
  manifest.json        counts + hashes + sources + build time

Guards (abort without publishing a broken list):
  * count < job.min_lines
  * count < previous_count * ratio_guard  (previous count read from prev_manifest_url)

Pure standard library; no third-party deps.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

# a valid DNS name / suffix label set (punycode xn-- is allowed, '-' allowed inside labels)
ALLOWED = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$")
BAD_CHARS = set("*()^$[]?\\+|, \t/\"'<>@#&=%!")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "smartdns-rules/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def normalize(entry: str):
    d = entry.strip().lower().lstrip(".")
    if not d or len(d) > 253:
        return None
    if any(c in d for c in BAD_CHARS):
        return None
    if not ALLOWED.match(d):
        return None
    return d


def collect(url: str, domains: set, regexes: list) -> None:
    data = json.loads(fetch(url))
    for rule in data.get("rules", []) or []:
        for key in ("domain", "domain_suffix"):
            for item in rule.get(key, []) or []:
                if isinstance(item, str):
                    n = normalize(item)
                    if n:
                        domains.add(n)
        for item in rule.get("domain_regex", []) or []:
            if isinstance(item, str):
                regexes.append(item)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_prev_manifest(url: str | None) -> dict:
    if not url:
        return {}
    try:
        return json.loads(fetch(url))
    except Exception as exc:  # noqa: BLE001 - first run / offline is fine
        print(f"[warn] no previous manifest ({exc})", file=sys.stderr)
        return {}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="dist")
    ap.add_argument("--sources", default="sources.json")
    ap.add_argument("--prev-manifest-url", default=None)
    ap.add_argument("--ratio-guard", type=float, default=None)
    args = ap.parse_args()

    cfg = json.loads(Path(args.sources).read_text(encoding="utf-8"))
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    prev_url = args.prev_manifest_url or cfg.get("prev_manifest_url")
    ratio = args.ratio_guard if args.ratio_guard is not None else float(cfg.get("ratio_guard", 0.5))
    prev_jobs = load_prev_manifest(prev_url).get("jobs", {})

    manifest = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "jobs": {},
    }

    for job in cfg["jobs"]:
        name = job["name"]
        domains: set = set()
        regexes: list = []
        for url in job["sources"]:
            n0 = len(domains)
            collect(url, domains, regexes)
            print(f"[{name}] {url} -> +{len(domains) - n0} domains")

        lines = sorted(domains)
        count = len(lines)

        min_lines = int(job.get("min_lines", 0))
        if count < min_lines:
            sys.exit(f"[guard] {name}: {count} < min_lines={min_lines}, abort")

        prev_count = prev_jobs.get(name, {}).get("count")
        if prev_count and count < prev_count * ratio:
            sys.exit(f"[guard] {name}: {count} < {prev_count} * {ratio}, abort")

        lst = out / f"{name}.lst"
        lst.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        digest = sha256_file(lst)
        (out / f"{name}.lst.sha256").write_text(f"{digest}  {name}.lst\n", encoding="ascii")

        uniq_regex = sorted(set(regexes))
        if uniq_regex:
            (out / f"regex-{name}.txt").write_text(
                "\n".join(uniq_regex) + "\n", encoding="utf-8", newline="\n"
            )

        manifest["jobs"][name] = {
            "count": count,
            "sha256": digest,
            "regex_count": len(uniq_regex),
            "sources": job["sources"],
        }
        print(f"[{name}] {count} domains, {len(uniq_regex)} regex dropped")

    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"done -> {out}")


if __name__ == "__main__":
    main()
