# Managed app configuration

TenantKeep On-Call reads an Intune app configuration policy at launch and whenever Intune
pushes a new one. Every key is optional. Without a policy the app behaves exactly as
described everywhere else on this site, and every default below is the safe one.

A policy can only take things away or ask for more care. It can switch a module off,
require more confirmation, keep the app to your own tenant, and require the app lock. It
cannot turn on a write an administrator has not turned on in the app.

A key the app does not recognise, or a value it cannot use, is ignored and listed in the
app under Settings, Managed by Your Organization, so a typo is visible instead of silent.

## Keys

| Key | Type | Values | Default | What it does |
|---|---|---|---|---|
| `modules.disabled` | string array, or a comma-separated string | `credentials`, `privilegedAccess`, `signInTriage`, `tenantPulse`, `conditionalAccess`, `security`, `deviceActions`, `userActions`, `groupWrites`, `notifications` | none | Removes the module from the app. `deviceActions` also hides the Settings switch that would enable them |
| `confirmation.level` | string | `standard`, `strict` | `standard` | `strict` makes every write ask at least once more than standard: sync, which normally runs on a tap, asks first |
| `tenant.pin` | string | your tenant ID, a GUID | none | The app works only in this tenant. An account from any other tenant is signed straight back out, and the MSP organization switcher is not offered |
| `appLock.required` | boolean, or the strings `true` and `false` | `true`, `false` | `false` | Face ID (or the passcode) to open the app, and the switch in Settings is replaced by "Required" |
| `breakGlass.upns` | string array, or a comma-separated string | sign-in addresses | none | Emergency access accounts watched by the break-glass notification for your own tenant, added to any the user lists |
| `groupWrite.scope` | string | `tagged`, `all`, `none` | `tagged` | Which groups the helpdesk may change membership of, when group changes ship |
| `groupWrite.administrativeUnit` | string | an administrative unit's name | `Helpdesk Managed Groups` | The unit whose groups count as helpdesk-managed under `tagged` |
| `groupWrite.prefix` | string | a short prefix such as `HD-` | none | Groups whose name starts with it count as helpdesk-managed under `tagged` |

## Example policy

In Intune: Apps, App configuration policies, Add, Managed devices, platform iOS/iPadOS,
the TenantKeep On-Call app, then Configuration settings format "Enter XML data":

```xml
<dict>
  <key>tenant.pin</key>
  <string>00000000-0000-0000-0000-000000000000</string>
  <key>appLock.required</key>
  <true/>
  <key>modules.disabled</key>
  <array>
    <string>deviceActions</string>
  </array>
  <key>confirmation.level</key>
  <string>strict</string>
  <key>breakGlass.upns</key>
  <array>
    <string>breakglass1@contoso.onmicrosoft.com</string>
    <string>breakglass2@contoso.onmicrosoft.com</string>
  </array>
</dict>
```

Replace the tenant ID with your own. The configuration designer works too: use the key
names above, type String for every key, and comma-separated values for the lists.

## What the app does with it

The policy is read from `com.apple.configuration.managed`, the dictionary iOS keeps for
managed apps. It never leaves the device and is never sent to Kainor. The source that
parses it is `LAPSlockKit/Sources/ManagedConfigKit/ManagedConfiguration.swift`, with a test
for every key.
