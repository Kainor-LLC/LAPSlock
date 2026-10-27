# TenantKeep alert relay

The relay passes an alert that a customer's own TenantKeep Watch run has encrypted for one
phone to Apple's push service, and keeps nothing. The contract is
[docs/RELAY-API.md](../docs/RELAY-API.md); this folder is its implementation, published so the
contract can be checked against the code as well as with a proxy.

| Folder | What |
|---|---|
| `function/` | The Azure Function, .NET 10 isolated worker. `RelayHandler` is the whole job; `RelayFunction` only reads the body and writes the answer. |
| `function/tests/` | xUnit: strict parsing, the offline entitlement check, the in-memory limits, Apple's answers mapped to the contract, and that no answer echoes what was sent. Includes a request built by the sender. |
| `sender/` | The PowerShell sender for Watch: `Hpke.cs` (RFC 9180, checked against the CFRG vectors by `Test-Hpke.ps1`) and `TenantKeepRelaySender.ps1`, with `Test-RelaySender.ps1`. |

The phone's side is `RelayKit` and the `RelayNotificationService` extension in the app.

## Run the tests

```
dotnet test relay/function/tests/TenantKeep.Relay.Tests
pwsh relay/sender/Test-RelaySender.ps1
pwsh relay/sender/Test-Hpke.ps1 -Vectors test-vectors.json
```

`test-vectors.json` is <https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json>.

## What it keeps

Nothing. No storage of its own, no table, no queue. The code holds no logger, so no request
field can be written down; the host logs at Warning and above. Rate limits are counters in
memory keyed by an HMAC under a key made at start-up (`RelayRateLimiter`), gone on restart.

## Configuration

| Setting | Value |
|---|---|
| `APNS_KEY_ID` | The APNs authentication key's id, from the Apple Developer account |
| `APNS_TEAM_ID` | The Apple team id |
| `APNS_KEYVAULT_KEY_ID` | The Key Vault key holding the APNs `.p8` key, imported as an EC P-256 key, non-exportable |
| `APNS_TOPIC` | `com.kainor.lapslock` (the default) |

The function's managed identity needs Key Vault Crypto User on that one key's vault, and
nothing else.
