#!/usr/bin/env python3
"""One-time sign-in for the Graph change watch's test account.

Runs the device code flow against the Kainor demo tenant with read-only delegated
scopes, then hands the refresh token straight to `gh secret set` on the private repo.
The token is never printed or written to disk. Run it again if the watch reports that
its sign-in failed.

    python3 bootstrap_token.py <tenant-id> <client-id> [owner/repo]

Needs the GitHub CLI signed in with access to the repo (default Kainor-LLC/LAPSlock-internal).
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Read-only, the scopes the live reads need. Nothing here can change the tenant.
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
]


def post(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=60) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        return json.loads(error.read() or b"{}")


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    tenant, client = argv[1], argv[2]
    repo = argv[3] if len(argv) > 3 else "Kainor-LLC/LAPSlock-internal"
    base = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
    scope = " ".join("https://graph.microsoft.com/" + s if "." in s else s for s in SCOPES)
    code = post(base + "devicecode", {"client_id": client, "scope": scope})
    if "device_code" not in code:
        print("Could not start the sign-in: " + code.get("error_description", str(code))[:300])
        return 1
    print(code["message"])
    print("Sign in as the watch's test account, not your own.")
    interval = int(code.get("interval", 5))
    deadline = time.time() + int(code.get("expires_in", 900))
    while time.time() < deadline:
        time.sleep(interval)
        result = post(base + "token", {
            "client_id": client,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": code["device_code"],
        })
        if "refresh_token" in result:
            for name, value in (("GW_TENANT_ID", tenant), ("GW_CLIENT_ID", client), ("GW_REFRESH_TOKEN", result["refresh_token"])):
                done = subprocess.run(["gh", "secret", "set", name, "--repo", repo], input=value, text=True, capture_output=True)
                if done.returncode != 0:
                    print("gh secret set " + name + " failed: " + done.stderr.strip())
                    return 1
            print("Stored GW_TENANT_ID, GW_CLIENT_ID and GW_REFRESH_TOKEN on " + repo + ".")
            return 0
        error = result.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        print("Sign-in failed: " + result.get("error_description", str(error))[:300])
        return 1
    print("The code expired. Run it again.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
