#!/usr/bin/env python3
"""Turns the checks' findings into one GitHub issue body, leaving out anything already
reported in an earlier issue, so each problem is raised once.

    python3 report.py --schema S.json --changelog C.json --feeds F.json --smoke K.json \\
        --known known.json --out body.md --status "schema=0 changelog=0 feeds=0 smoke=3"

known.json is `gh issue list --label graph-watch --state all --json body`. Prints the
number of new findings; writes nothing when there are none.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def arg(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


def read(path):
    if not path or not Path(path).exists():
        return []
    try:
        return json.loads(Path(path).read_text() or "[]")
    except ValueError:
        return []


def fingerprint(section, finding):
    key = section + "|" + finding.get("id", finding.get("guid", "")) + "|" + finding.get("problem", finding.get("title", ""))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def main(argv):
    known_bodies = " ".join(i.get("body", "") for i in read(arg(argv, "--known")))
    sections = [
        ("Schema", "A path, field, action or parameter the app uses is gone from Graph's published schema.", read(arg(argv, "--schema"))),
        ("Live reads", "A real read against the Kainor tenant answered differently from what the app expects.", read(arg(argv, "--smoke"))),
        ("Changelog", "Microsoft's Graph changelog removes, renames or deprecates something the app uses.", read(arg(argv, "--changelog"))),
        ("Threat Digest feeds", "A public feed the Threat Digest parses changed shape or stopped answering.", read(arg(argv, "--feeds"))),
    ]
    # A check that could not run at all is raised once a week while it stays down.
    status = arg(argv, "--status") or ""
    week = datetime.now(timezone.utc).strftime("%G-W%V")
    down = []
    for part in status.split():
        name, _, code = part.partition("=")
        if code == "2":
            reason = "its sign-in failed; run bootstrap_token.py again" if name == "smoke" else "it could not read its source"
            down.append({"id": name, "problem": "did not run this week (" + week + "): " + reason})
    sections.insert(0, ("Checks that did not run", "The watch is partly blind until this is fixed.", down))
    lines = []
    new = 0
    for title, why, findings in sections:
        fresh = []
        for f in findings:
            if f.get("info"):
                continue
            fp = fingerprint(title, f)
            if fp in known_bodies:
                continue
            fresh.append((fp, f))
        if not fresh:
            continue
        new += len(fresh)
        lines += ["## " + title, "", why, ""]
        for fp, f in fresh:
            if "guid" in f:
                lines.append("- **" + f["published"] + ", " + "/".join(f.get("versions", [])) + ", " + f["title"] + "**: " + f["text"] + " Calls: " + ", ".join(f["calls"]) + " <!-- fp:" + fp + " -->")
            else:
                where = f.get("kit", "")
                lines.append("- **" + f["id"] + "**" + (" (" + where + (", " + f["version"] if f.get("version") else "") + ")" if where else "") + ": " + f["problem"] + " <!-- fp:" + fp + " -->")
        lines.append("")
    if new:
        lines += [
            "## What to do",
            "",
            "Find the call by its id in `scripts/graph-watch/manifest.json` in the app repo; the kit named next to it makes the call. Fix it there, run the gates, and ship as an expedited App Store review if customers are affected.",
            "",
            "Each item is reported once. Closing this issue does not bring it back.",
        ]
        if status:
            lines += ["", "Exit codes: " + status]
        Path(arg(argv, "--out")).write_text("\n".join(lines) + "\n")
    print(new)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
