#!/usr/bin/env python3
"""Builds docs/glossary/index.html from the glossary the app ships.

The app bundles LAPSlockKit/Sources/SignInTriageKit/Resources/ErrorGlossary.json so the
plain-English line for a sign-in error works with no network. This script publishes the
same file on kainor.com, so the phone and the page never disagree. The page borrows its
head, header and footer from docs/how-it-works/index.html, so a style change there carries
over on the next run.

    python3 scripts/build-glossary.py
"""
import html
import json
import pathlib
import re

root = pathlib.Path(__file__).resolve().parent.parent
glossary = json.loads((root / "LAPSlockKit/Sources/SignInTriageKit/Resources/ErrorGlossary.json").read_text())
template = (root / "docs/how-it-works/index.html").read_text()

head = template[: template.index("</head>")]
head = head.replace("<title>How LAPSlock works · Kainor LLC</title>", "<title>Sign-in error glossary · Kainor LLC</title>")
head = re.sub(
    r'<meta name="description" content="[^"]*">',
    '<meta name="description" content="Plain-English explanations of the Microsoft Entra sign-in error codes an on-call administrator meets most, with what to do about each. The same glossary ships inside TenantKeep On-Call.">',
    head,
)

header_start = template.index("<header")
header_end = template.index("</header>") + len("</header>")
header = template[header_start:header_end]
header = header.replace('<span class="eyebrow">LAPSlock</span>', '<span class="eyebrow">Sign-in triage</span>')
header = header.replace("<h1 class=\"display\">How it works</h1>", "<h1 class=\"display\">Sign-in error glossary</h1>")
header = re.sub(r'<p class="updated">[^<]*</p>', '<p class="updated">Built from the glossary inside the app</p>', header)

footer = template[template.index("<footer"):]

rows = []
for entry in sorted(glossary["entries"], key=lambda e: e["code"]):
    rows.append(
        "        <tr>\n"
        f"          <td><code id=\"{entry['code']}\">{entry['code']}</code></td>\n"
        f"          <td><strong>{html.escape(entry['title'])}</strong><br>{html.escape(entry['meaning'])}</td>\n"
        f"          <td>{html.escape(entry['action'])}</td>\n"
        "        </tr>"
    )

main = f"""
<main>
  <div class="wrap">
    <div class="summary">
      <h2>What this is</h2>
      <p><strong>The error codes Microsoft Entra returns when a sign-in fails, in plain English, with
      what to do about each.</strong> TenantKeep On-Call shows the same line beside every failed sign-in in its
      People module, so the person on call gets the answer without a search. This page is the
      same glossary, published for everyone.</p>
      <p>Each code links directly: add <code>#50074</code> to the address to share one entry. Microsoft's
      full reference is the authority; this is the one-line version for 2 am.</p>
    </div>

    <h2 class="sec" id="codes">Codes</h2>
    <div class="table-scroll">
    <table>
      <thead>
        <tr><th>Code</th><th>What it means</th><th>What to do</th></tr>
      </thead>
      <tbody>
{chr(10).join(rows)}
      </tbody>
    </table>
    </div>

    <div class="note">
      <strong>Missing one?</strong> The glossary grows from real tickets. If a code you meet is not
      here, send it with one line about what fixed it and it goes in the next release of the app and
      this page together.
    </div>
  </div>
</main>

"""

out = root / "docs/glossary/index.html"
out.write_text(head + "</head>\n<body>\n\n" + header + "\n" + main + footer)
print(f"wrote {out.relative_to(root)} with {len(rows)} entries")
