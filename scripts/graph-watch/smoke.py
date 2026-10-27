#!/usr/bin/env python3
"""The live half of the Graph change watch: real reads against the Kainor tenant.

Signs in as the watch's test account with a stored refresh token (delegated, like the
app), makes each manifest call's smoke read, and checks the answer: the status, that a
list is still a list, and that every field the app selects still comes back. It also
reads the tenant's Message Center for posts that name an API the app uses.

A read whose manifest entry requires a plan the tenant lacks (P1, P2, Intune, Defender)
is skipped, not failed: GW_TENANT_FEATURES lists what the tenant has, comma separated.
A licensing refusal on a read that was expected to work is reported as such.

Reads only. A call that is not a GET, or a path that could return a password, a recovery
key or a pass, is refused before any request is made. Nothing from a response is printed
except Graph's own error code and message; tokens are never printed.

    GW_TENANT_ID=... GW_CLIENT_ID=... GW_REFRESH_TOKEN=... GW_TENANT_FEATURES=P1,Intune \\
        python3 smoke.py manifest.json [--json OUT] [--new-token-file FILE]

--new-token-file writes the rotated refresh token there (mode 600) for the workflow to
store back. Exit 0 when every read answers as expected, 1 when one does not, 2 when the
sign-in failed, 3 when the credentials are not configured (the workflow skips the step).
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

GRAPH = "https://graph.microsoft.com/"
# Paths and selects that return a secret. The live check never sends one.
FORBIDDEN = re.compile(r"\$select=[^&]*\b(credentials|key|temporaryAccessPass)\b|recoveryKeys/[^?/]+|retrieveDeviceLocalAdminAccountDetail|temporaryAccessPassMethods", re.I)
GRAPH_WORDS = re.compile(r"\b(Microsoft Graph|Graph API)\b", re.I)
LICENSE_CODES = re.compile(r"NonPremiumTenant|PremiumLicense|LicenseRequired|not licensed|license", re.I)
BREAK_WORDS = re.compile(r"\b(retir\w*|deprecat\w*|remov\w*|no longer|breaking|end of support)\b", re.I)


def refuse(call):
    smoke = call.get("smoke") or ""
    if call["method"] != "GET":
        return "not a GET"
    if FORBIDDEN.search(smoke):
        return "could return a secret"
    return None


def token(tenant, client, refresh):
    body = urllib.parse.urlencode({
        "client_id": client,
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "scope": "https://graph.microsoft.com/.default offline_access",
    }).encode()
    url = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=60) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read())
            reason = detail.get("error", "") + ": " + (detail.get("error_description", "").split("\r\n")[0])
        except ValueError:
            reason = "HTTP " + str(error.code)
        raise RuntimeError("sign-in failed, " + reason)
    return data["access_token"], data.get("refresh_token")


def get(access, version, path):
    quoted = urllib.parse.quote(path, safe="/?&=$,'():")
    request = urllib.request.Request(GRAPH + version + quoted, headers={
        "Authorization": "Bearer " + access,
        "ConsistencyLevel": "eventual",
        "User-Agent": "TenantKeep-GraphWatch/1",
    })
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read() or b"{}")
        except ValueError:
            return error.code, {}


def device_user(access):
    """A person who is the primary user of a managed device, for reads about someone's
    devices. The watch account has none, and Intune answers 404 for people it does not know."""
    status, body = get(access, "v1.0", "/deviceManagement/managedDevices?$top=20&$select=userId")
    if status != 200:
        return None
    for item in body.get("value", []):
        if item.get("userId"):
            return item["userId"]
    return None


def check(access, call, context=None):
    path = call["smoke"]
    for key, value in (context or {}).items():
        path = path.replace("{" + key + "}", value)
    status, body = get(access, call["version"], path)
    if status in call.get("smokeAllow", []):
        return []
    if status != 200:
        err = body.get("error", {}) if isinstance(body, dict) else {}
        if status == 403 and LICENSE_CODES.search(str(err.get("code", "")) + " " + str(err.get("message", ""))):
            return ["the tenant refused this read for licensing; if Kainor dropped " + "/".join(call.get("requires", ["a plan"])) + ", remove it from GW_TENANT_FEATURES"]
        return ["HTTP " + str(status) + " " + str(err.get("code", "")) + ": " + str(err.get("message", ""))[:300]]
    problems = []
    items = body.get("value") if isinstance(body, dict) else None
    sample = items[0] if isinstance(items, list) and items else (body if items is None else None)
    if "value" in body and not isinstance(items, list):
        problems.append("value is no longer a list")
    if sample is not None and "$select=" in path:
        selected = path.split("$select=")[1].split("&")[0].split(",")
        missing = [f for f in selected if f not in sample]
        if missing:
            problems.append("response no longer carries " + ", ".join(missing))
    return problems


def message_center(access, manifest):
    """Message Center posts from the last week that name an API the app uses and retire,
    deprecate or remove something."""
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    status, body = get(access, "v1.0", "/admin/serviceAnnouncement/messages?$filter=lastModifiedDateTime ge " + since)
    if status != 200:
        return [{"id": "messageCenter", "problem": "could not read Message Center, HTTP " + str(status)}]
    # Only names specific enough to mean the API: camelCase path segments such as
    # managedDevices or riskyUsers, never plain words like security or messages.
    names = set()
    for call in manifest["calls"]:
        for seg in call["path"].split("/"):
            seg = seg.split("(")[0]
            if seg and not seg.startswith("{") and re.search(r"[a-z][A-Z]", seg):
                names.add(seg)
    found = []
    for post in body.get("value", []):
        text = (post.get("title") or "") + " " + re.sub(r"<[^>]+>", " ", (post.get("body") or {}).get("content") or "")
        if not (GRAPH_WORDS.search(text) and BREAK_WORDS.search(text)):
            continue
        named = sorted(n for n in names if re.search(r"(?<![A-Za-z])" + re.escape(n) + r"(?![A-Za-z])", text, re.I))
        if named:
            found.append({"id": "messageCenter." + str(post.get("id")), "problem": (post.get("title") or "")[:200] + " (names " + ", ".join(named) + ")"})
    return found


def main(argv):
    manifest = json.loads(Path(argv[1]).read_text())
    out = argv[argv.index("--json") + 1] if "--json" in argv else None
    new_token_file = argv[argv.index("--new-token-file") + 1] if "--new-token-file" in argv else None
    tenant, client, refresh = (os.environ.get(k) for k in ("GW_TENANT_ID", "GW_CLIENT_ID", "GW_REFRESH_TOKEN"))
    if not (tenant and client and refresh):
        print("Live check not configured: GW_TENANT_ID, GW_CLIENT_ID and GW_REFRESH_TOKEN are needed.")
        return 3
    try:
        access, rotated = token(tenant, client, refresh)
    except Exception as error:
        print(str(error))
        if out:
            Path(out).write_text(json.dumps([{"id": "signIn", "problem": str(error)}], indent=2))
        return 2
    if new_token_file and rotated:
        fd = os.open(new_token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(rotated)
    features = {f.strip().lower() for f in os.environ.get("GW_TENANT_FEATURES", "").split(",") if f.strip()}
    context = {}
    if any("{deviceUserId}" in (c.get("smoke") or "") for c in manifest["calls"]):
        found = device_user(access)
        if found:
            context["deviceUserId"] = found
    findings = []
    checked = 0
    skipped = []
    for call in manifest["calls"]:
        if not call.get("smoke"):
            continue
        if any(r.lower() not in features for r in call.get("requires", [])):
            skipped.append(call["id"])
            continue
        filled = call["smoke"]
        for key, value in context.items():
            filled = filled.replace("{" + key + "}", value)
        if re.search(r"\{[A-Za-z]+\}", filled):
            skipped.append(call["id"] + " (nobody to read it for: no managed device has a primary user)")
            continue
        reason = refuse(call)
        if reason:
            findings.append({"id": call["id"], "kit": call["kit"], "problem": "smoke read refused, " + reason + "; fix the manifest"})
            continue
        checked += 1
        for problem in check(access, call, context):
            findings.append({"id": call["id"], "kit": call["kit"], "version": call["version"], "problem": problem})
    findings += message_center(access, manifest)
    for f in findings:
        print("BREAK " + f["id"] + ": " + f["problem"])
    if skipped:
        print("Not read live: " + ", ".join(skipped))
    print(str(checked) + " live reads, " + str(len(skipped)) + " skipped, " + str(len(findings)) + " problems")
    if out:
        Path(out).write_text(json.dumps(findings, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
