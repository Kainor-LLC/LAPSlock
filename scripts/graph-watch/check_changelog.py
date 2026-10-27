#!/usr/bin/env python3
"""Reads the Microsoft Graph changelog and flags entries that could break the app.

An entry is flagged when it removes, renames, deprecates or retypes something and names a
type, action or field from manifest.json. Additions are ignored: they cannot break a call.
The types come from walking each manifest path through the schema, as check_schema does.

    python3 check_changelog.py manifest.json [--days N] [--metadata-dir DIR] [--feed FILE] [--json OUT]

Exit 0 with nothing flagged, 1 with something flagged, 2 when the feed could not be read.
"""
import html
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import check_schema  # noqa: E402

FEED = "https://developer.microsoft.com/en-us/graph/changelog/rss"
BREAKING = re.compile(r"\b(remov\w*|deprecat\w*|renam\w*|retir\w*|no longer|changed the (?:type|data type)|replaced)\b", re.I)


def keywords(manifest, schemas):
    """For each call: the types it touches, and the members it uses on them (fields it
    reads or sends, the action or function it calls)."""
    out = {}
    for call in manifest["calls"]:
        schema = schemas[call["version"]]
        current, _, op, problems = check_schema.resolve(schema, call["path"])
        members = set(call.get("select", []) + call.get("expand", []) + call.get("parameters", []))
        types = set()
        if current and not problems:
            types.add(current.split(".")[-1])
        if op is not None:
            members.add(op.get("Name"))
            for param in op.findall(check_schema.EDM + "Parameter")[:1]:
                bound, _ = check_schema.strip_collection(schema.full(param.get("Type")))
                types.add(bound.split(".")[-1])
        out[call["id"]] = (types, members)
    return out


def sentence_breaks(sentence, types, members):
    """True when the sentence removes or changes one of the types, or a used member of one."""
    if not BREAKING.search(sentence) or not any(word_in(t, sentence) for t in types):
        return False
    whole = re.search(r"\b(?:remov|deprecat|renam|retir)\w* the (\w+) (?:resource|entity|type)\b", sentence, re.I)
    if whole and whole.group(1) in types:
        return True
    return any(word_in(m, sentence) for m in members)


def parse_date(text):
    try:
        value = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        try:
            value = datetime.strptime(text.strip(), "%a, %d %b %Y %H:%M:%S Z")
        except ValueError:
            return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def plain(text):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text or ""))).strip()


def word_in(word, text):
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])", text) is not None


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    manifest = json.loads(Path(argv[1]).read_text())
    days = int(argv[argv.index("--days") + 1]) if "--days" in argv else 3
    metadata_dir = argv[argv.index("--metadata-dir") + 1] if "--metadata-dir" in argv else None
    out = argv[argv.index("--json") + 1] if "--json" in argv else None
    try:
        schemas = {v: check_schema.Schema(check_schema.load(v, metadata_dir)) for v in ("v1.0", "beta")}
        if "--feed" in argv:
            raw = Path(argv[argv.index("--feed") + 1]).read_bytes()
        else:
            with urllib.request.urlopen(FEED, timeout=120) as response:
                raw = response.read()
        items = ET.fromstring(raw).iter("item")
    except Exception as error:
        print("Could not read the Graph changelog or schema: " + str(error))
        return 2

    since = datetime.now(timezone.utc) - timedelta(days=days)
    keys = keywords(manifest, schemas)
    findings = []
    seen = 0
    for item in items:
        published = parse_date(item.findtext("pubDate") or "")
        if published is None or published < since:
            continue
        seen += 1
        text = plain(item.findtext("description"))
        if not BREAKING.search(text):
            continue
        versions = [c.text for c in item.findall("category") if c.text in ("v1.0", "beta")]
        hits = set()
        flagged = []
        for sentence in re.split(r"(?<=[.])\s+", text):
            for call in manifest["calls"]:
                if versions and call["version"] not in versions:
                    continue
                types, members = keys[call["id"]]
                if sentence_breaks(sentence, types, members):
                    hits.add(call["id"])
                    flagged.append(sentence)
        if hits:
            findings.append({
                "guid": item.findtext("guid"),
                "title": item.findtext("title"),
                "published": published.date().isoformat(),
                "versions": versions,
                "text": " ".join(dict.fromkeys(flagged))[:800],
                "calls": sorted(hits),
            })
    for f in findings:
        print("FLAG  " + f["published"] + " " + "/".join(f["versions"]) + " " + f["title"] + ": " + f["text"][:200] + " -> " + ", ".join(f["calls"]))
    print(str(seen) + " changelog entries in the last " + str(days) + " days, " + str(len(findings)) + " flagged")
    if out:
        Path(out).write_text(json.dumps(findings, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
