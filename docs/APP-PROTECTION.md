# Intune App Protection

TenantKeep On-Call can be protected by a Microsoft Intune app protection policy, on a phone
your organization does not manage. This page says what makes that possible, what it costs in
what the app can promise, and how to turn it on.

Last checked against the code on 2026-11-23.

## The One Closed-Source Component

App protection is enforced by Microsoft's Intune App SDK, which Microsoft ships as a signed
binary with no source. It is the only part of the app whose source is not in this repository.
Everything Kainor wrote is here to read; this one component is Microsoft's, and you are
trusting Microsoft for it, as you already do for Intune.

- Version 22.2.0, from <https://github.com/microsoftconnect/ms-intune-app-sdk-ios>, pinned to
  that exact version. Signed by Microsoft Corporation, team `UBF8T346G9`.
- Building the app from source downloads it from Microsoft's repository, about 3 GB.
- It is why the app needs iOS 18 or later.

What holds it in place, and what you can check:

- The iPhone and iPad app links it. The package that holds every module does not depend on
  it, so no module can import it: not the one that handles passwords, nor any other. The Mac
  menu bar app, the watch app and the notification extension do not link it.
- One file in the app imports it, `App/lapslock/lapslock/AppProtection.swift`.
- `scripts/isolation-check.sh` fails if any of that stops being true.

What that does not give you. The SDK runs inside the app's process. Once a policy is in
force it places itself between the app and the pasteboard, files, the network and the
Keychain, for the whole app, the screen that shows a password included. That is how a policy
is enforced, and it is what an organization asks for when it targets the app with one. With
no policy in force none of that is installed.

## With No Policy

The app behaves as it does without the SDK, with two exceptions that apply to every
install, protected or not:

- **One request to Microsoft at launch.** The SDK fetches its own settings from
  `config.edge.skype.com`, and again from time to time while the app is used. The request
  carries an identifier the SDK makes up for the install, the SDK's version and the iOS
  version. It carries no account, no tenant and nothing from the app. As seen on
  2026-11-23:
  `https://config.edge.skype.com/config/v1/Intune/1.0?agents=CLI_iOSMAM&SDKBuildType=Dynamic&tenantID=&clientID=<an ID made up for the install>&SDKVersion=22.2.0&Environment=unknown&OSVersion=27.0`
  Microsoft documents no setting that stops it.
- **The SDK's own storage.** It keeps a few items of its own in the Keychain, in the group
  `com.microsoft.intune.mam`, and a folder, `Library/.IntuneMAM`. The app neither reads nor
  writes them.

The SDK's usage reporting to Microsoft is turned off (`MAMTelemetryDisabled`). No reporting
host was contacted in testing.

## Turning It On

1. **Approve TenantKeep App Protection** at <https://tenantkeep.app/consent/>. It is an app
   registration of its own, `eaea8770-7305-4806-ae1c-7a03d2ef28fe`, holding one delegated
   permission, `DeviceManagementManagedApps.ReadWrite`, on Microsoft's Mobile Application
   Management service. That permission lets the SDK read and write the signed-in person's
   own app management record. It is not a Microsoft Graph permission and gives no access to
   your directory. It is separate so that the app you sign in through still holds read
   permissions only, and an organization that does not use app protection never approves it.
2. **Create an iOS app protection policy** in Intune. TenantKeep On-Call is not in
   Microsoft's list of apps, so add it as a custom app by its bundle ID,
   `com.kainor.lapslock`, and assign the policy to a group. Each person needs an Intune
   licence. `tools/setup/New-AppProtectionTestPolicy.ps1` makes a small one to try.
3. **Sign in.** Where the organization approved the registration for everyone, the app signs
   the person in to it and asks Intune by itself. Otherwise the person turns it on once in
   Settings, General, Intune App Protection. The first time a policy arrives, the SDK closes
   the app so it can start again protected.

The SDK never signs in. It asks the app for a token, and the app gets one through TenantKeep
App Protection, silently, for the person signed in, in their own organization. It is given a
token for that one service and for nothing else.

## What a Policy Changes

- **The PIN and data transfer.** Enforced by the SDK: a PIN or biometrics to open the app,
  and limits on copying and sharing out of it.
- **Notifications.** If the policy keeps organization data out of notifications, every
  alert says only "You have an alert. Open TenantKeep to read it." If it stops notifications,
  the app posts none and unregisters the phone from Instant alerts, because that is the only
  way to stop a relayed alert from appearing. Threat Digest news is public, and is shown
  unless notifications are stopped altogether.
- **The Apple Watch.** The SDK does not exist on the watch, so a policy cannot protect what
  is sent there. While a policy is in force the phone sends the watch nothing and does
  nothing it asks, unless you set `watch.allowed` (see
  [MANAGED-CONFIG.md](MANAGED-CONFIG.md)).
- **Configuration.** The keys in [MANAGED-CONFIG.md](MANAGED-CONFIG.md) also arrive through
  an app configuration policy for managed apps, so they reach a phone that is not enrolled.
- **Sign-out.** The app tells Intune the person has left before it deletes their sign-in,
  and waits at most ten seconds to do it.
- **A selective wipe.** When Intune orders your data off the device, the app removes more
  than sign-out does: every sign-in, the reveal count, the licence record, the list of
  customer organizations, notification choices and break-glass accounts, the Instant alerts
  key, the shift log, saved searches, its files and its settings. It tells Kainor's alert
  service the phone has left first, and shows no Microsoft sign-out page.

Settings, General shows whether a policy is applied and what it is doing to notifications
and the watch.

## What It Does Not Do

- **Conditional Access cannot require it yet.** The grant "Require app protection policy"
  works for apps Microsoft has listed, and TenantKeep On-Call is not listed yet. You can
  apply a policy; you cannot yet make sign-in depend on one.
- **The Mac.** The Mac menu bar app has no SDK and no app protection. The iPhone app
  running on a Mac has not been tested under a policy.
- **A person can decline.** Without Conditional Access, someone who never signs in to
  TenantKeep App Protection is not protected. Approving the registration for the whole
  organization makes the app do it without asking.

## What Microsoft Receives

With a policy, the SDK talks to Intune as the signed-in person: it enrols the app, fetches
the policy, and checks in again about every eight hours. Microsoft's handling of that is
described in the [Microsoft Intune Privacy
Statement](https://learn.microsoft.com/legal/intune/microsoft-intune-privacy-statement).
Kainor receives none of it.

The hosts the SDK names for Microsoft's commercial cloud are `config.edge.skype.com`,
`login.microsoftonline.com`, `graph.microsoft.com` and hosts under `manage.microsoft.com`.
The launch request above was observed directly. The requests made once a policy applies
were not captured with a proxy, so this list comes from the binary and not from watching
it; [NETWORK-TRANSPARENCY.md](NETWORK-TRANSPARENCY.md) says how to check.

## What Has Been Seen Working

On 2026-11-23, on an iPhone that Intune does not manage, in one tenant: a policy arrived
through TenantKeep App Protection, the app asked for a PIN, stayed signed in, refused a paste
into Notes, still revealed a password, and a selective wipe from Intune left it signed out.
Notifications without details, the watch and configuration through the app channel are
written and tested in code, and had not been seen under a policy when this was written.
