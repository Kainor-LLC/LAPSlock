#!/usr/bin/env python3
"""Checks the public feeds the Threat Digest reads still answer in the shape it parses.

    python3 check_feeds.py manifest.json [--json OUT]

Exit 0 when every feed answers as expected, 1 when one does not.
"""
import json
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


def check(feed):
    request = urllib.request.Request(feed["url"], headers={"User-Agent": "TenantKeep-GraphWatch/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read()
    except Exception as error:
        return ["unreachable: " + str(error)]
    if feed["kind"] == "rss":
        try:
            root = ET.fromstring(body)
        except ET.ParseError as error:
            return ["not XML any more: " + str(error)]
        if root.find("channel/item") is None and root.find("{http://www.w3.org/2005/Atom}entry") is None:
            return ["no items in the feed"]
        return []
    try:
        data = json.loads(body)
    except ValueError as error:
        return ["not JSON any more: " + str(error)]
    problems = [key + " is missing" for key in feed.get("keys", []) if key not in data]
    if problems:
        return problems
    items = data[feed["keys"][0]] if feed.get("keys") else []
    if feed.get("itemKeys") and items:
        problems += ["items have no " + key for key in feed["itemKeys"] if key not in items[0]]
    return problems


def main(argv):
    manifest = json.loads(Path(argv[1]).read_text())
    out = argv[argv.index("--json") + 1] if "--json" in argv else None
    findings = []
    for feed in manifest.get("feeds", []):
        for problem in check(feed):
            findings.append({"id": feed["id"], "kit": feed["kit"], "problem": problem})
            print("BREAK " + feed["id"] + ": " + problem)
    print(str(len(manifest.get("feeds", []))) + " feeds checked, " + str(len(findings)) + " broken")
    if out:
        Path(out).write_text(json.dumps(findings, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
