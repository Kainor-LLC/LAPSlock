#!/usr/bin/env python3
"""One-time sign-in for the Graph change watch's account.

Opens the browser on this Mac for an ordinary sign-in (authorization code with PKCE and
a localhost redirect), with read-only delegated scopes, then hands the refresh token
straight to `gh secret set` on the private repo. The token is never printed or written
to disk. Run it again if the watch reports that its sign-in failed.

Not the device code flow: tenants rightly block it with Conditional Access, and a token
that starts as a device code stays marked as one when it is refreshed.

    python3 bootstrap_token.py <tenant-id> <client-id> [owner/repo] [--login-hint UPN]

The browser asks for a fresh sign-in even if you are already signed in, so sign in as
the watch account, not your own. Needs the GitHub CLI signed in with access to the repo
(default Kainor-LLC/LAPSlock-internal), and the app registration's public client
redirect URIs to include http://localhost (setup-graph-watch.ps1 adds it).
"""
import base64
import hashlib
import http.server
import json
import secrets
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

# Read-only, the scopes the live reads need. Nothing here can change the tenant.
# setup-graph-watch.ps1 in the private repo consents exactly this list.
SCOPES = [
    "offline_access",
    "User.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceLocalCredential.ReadBasic.All",
    "BitLockerKey.ReadBasic.All",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleAssignmentSchedule.Read.Directory",
    "RoleManagementPolicy.Read.Directory",
    "PrivilegedEligibilitySchedule.Read.AzureADGroup",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "Directory.Read.All",
    "ServiceHealth.Read.All",
    "ServiceMessage.Read.All",
    "Application.Read.All",
    "SecurityEvents.Read.All",
    "SecurityIncident.Read.All",
    "IdentityRiskyUser.Read.All",
    "UserAuthenticationMethod.Read.All",
    "ThreatHunting.Read.All",
    "PrivilegedAssignmentSchedule.Read.AzureADGroup",
]

PAGE = b"""<!doctype html><meta charset="utf-8"><title>Graph watch</title>
<body style="font-family:-apple-system,sans-serif;padding:3em">
<h2>Signed in.</h2><p>You can close this tab and go back to the terminal.</p></body>"""


def post(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=60) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        return json.loads(error.read() or b"{}")


def wait_for_code(state):
    """Serves one request on a free localhost port and returns (port, result holder, thread)."""
    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if query.get("state", [""])[0] != state:
                self.send_response(400)
                self.end_headers()
                return
            result["code"] = query.get("code", [None])[0]
            result["error"] = query.get("error_description", query.get("error", [None]))[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 600
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    return server.server_address[1], result, thread


def store(repo, tenant, client, refresh):
    for name, value in (("GW_TENANT_ID", tenant), ("GW_CLIENT_ID", client), ("GW_REFRESH_TOKEN", refresh)):
        done = subprocess.run(["gh", "secret", "set", name, "--repo", repo], input=value, text=True, capture_output=True)
        if done.returncode != 0:
            print("gh secret set " + name + " failed: " + done.stderr.strip())
            return False
    return True


def main(argv):
    hint = None
    if "--login-hint" in argv:
        i = argv.index("--login-hint")
        hint = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if len(argv) < 3:
        print(__doc__)
        return 2
    tenant, client = argv[1], argv[2]
    repo = argv[3] if len(argv) > 3 else "Kainor-LLC/LAPSlock-internal"
    base = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
    scope = " ".join("https://graph.microsoft.com/" + s if "." in s else s for s in SCOPES)

    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    port, result, thread = wait_for_code(state)
    redirect = "http://localhost:" + str(port)
    params = {
        "client_id": client,
        "response_type": "code",
        "redirect_uri": redirect,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
    }
    if hint:
        params["login_hint"] = hint
    url = base + "authorize?" + urllib.parse.urlencode(params)
    print("Opening the browser. Sign in as the watch account, not your own.")
    print("If nothing opens, paste this into a private window:")
    print(url)
    webbrowser.open(url)
    thread.join(600)
    if not result.get("code"):
        print("Sign-in did not complete: " + str(result.get("error") or "no answer within ten minutes"))
        return 1
    tokens = post(base + "token", {
        "client_id": client,
        "grant_type": "authorization_code",
        "code": result["code"],
        "redirect_uri": redirect,
        "code_verifier": verifier,
        "scope": scope,
    })
    if "refresh_token" not in tokens:
        print("Sign-in failed: " + tokens.get("error_description", str(tokens.get("error")))[:400])
        return 1
    if not store(repo, tenant, client, tokens["refresh_token"]):
        return 1
    print("Stored GW_TENANT_ID, GW_CLIENT_ID and GW_REFRESH_TOKEN on " + repo + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
