#!/usr/bin/env python3
"""Lint lists/ai-domains.txt.

Enforces the format the Zeek input framework expects and the acceptance
rules from CONTRIBUTING.md:

  - first line is exactly "#fields\tdomain"
  - one lowercase domain per line, no blanks, no comments, no whitespace
  - every entry has at least two labels (no bare TLDs)
  - no duplicates
  - no entry that is a subdomain of another entry (suffix matching makes
    the longer one redundant)
  - no bare CDN / cloud-provider domains where a match does not mean
    "AI service"

Exit 0 when clean; exit 1 with one line per problem otherwise.
"""

import re
import sys

HEADER = "#fields\tdomain"

# Domains too broad to ever appear as a bare entry: a match would flag
# ordinary, non-AI traffic. Subdomain entries (openai.azure.com,
# dashscope.aliyuncs.com) remain fine — this list is exact-match.
TOO_BROAD = {
    "akamai.net",
    "akamaiedge.net",
    "aliyuncs.com",
    "amazonaws.com",
    "apple.com",
    "azure.com",
    "azurewebsites.net",
    "cloudflare.com",
    "cloudfront.net",
    "fastly.net",
    "github.com",
    "github.io",
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "windows.net",
}

LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
DOMAIN_RE = re.compile(rf"^{LABEL}(?:\.{LABEL})+$")


def main(path: str) -> int:
    problems = []
    entries = {}  # domain -> line number

    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()

    if not lines or lines[0] != HEADER:
        problems.append(f"line 1: first line must be exactly {HEADER!r}")

    for n, line in enumerate(lines[1:], start=2):
        if line == "":
            problems.append(f"line {n}: blank line")
            continue
        if line.startswith("#"):
            problems.append(f"line {n}: comment lines are not allowed")
            continue
        if line != line.strip() or "\t" in line or " " in line:
            problems.append(f"line {n}: whitespace in entry {line!r}")
            continue
        if line != line.lower():
            problems.append(f"line {n}: {line!r} must be lowercase")
            continue
        if not DOMAIN_RE.match(line):
            problems.append(f"line {n}: {line!r} is not a valid domain")
            continue
        if line in TOO_BROAD:
            problems.append(
                f"line {n}: {line!r} is too broad — a match would not mean "
                f"'AI service'; use a specific subdomain instead"
            )
        if line in entries:
            problems.append(f"line {n}: duplicate of line {entries[line]} ({line!r})")
            continue
        entries[line] = n

    # Suffix matching means "openai.com" already covers "api.openai.com";
    # the longer entry is redundant and should be dropped.
    for domain, n in entries.items():
        labels = domain.split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in entries:
                problems.append(
                    f"line {n}: {domain!r} is redundant — already covered by "
                    f"{parent!r} (line {entries[parent]})"
                )
                break

    for p in problems:
        print(f"{path}:{p}", file=sys.stderr)
    if not problems:
        print(f"{path}: OK ({len(entries)} entries)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "lists/ai-domains.txt"))
