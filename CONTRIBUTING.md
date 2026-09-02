# Contributing to LAPSlock

Thank you for looking. Here is how this repository works, and why.

## Issues: yes. Pull requests: no.

**Bug reports and feature requests are welcome as GitHub Issues.** Pull requests are not
accepted and are closed automatically.

That is not a comment on anyone's code. LAPSlock is source-available under PolyForm Strict
with an additional permission for security review — it is not open source, and Kainor LLC
must remain the sole copyright holder so the license can be enforced and, if ever necessary,
changed without tracking down every past contributor for consent. Accepting a patch would
compromise that, however small the patch.

If you have found a bug, an Issue describing it is exactly as useful as a fix would have
been, and it will be credited in the release notes if you want.

## Before you file anything: no credentials

This app handles local administrator passwords and BitLocker recovery keys. **Never paste
one into an Issue**, not even a redacted one, not even from a test tenant. Do not paste
tenant IDs, device names, user principal names, or Graph responses either — describe them
instead. The issue templates ask you to confirm this, and an Issue containing a credential
will be deleted rather than edited, because GitHub keeps edit history.

If the problem *is* that a credential ended up somewhere it should not be, that is a
security vulnerability. Do not open an Issue. Follow [`SECURITY.md`](SECURITY.md) and email
instead.

## What makes a report useful

- The app version (Settings → About) and the iOS version.
- Whether you were in demo mode or signed in.
- What you did, what you expected, what happened.
- If it is an auth or Graph failure: the diagnostics report from Settings → *Gather
  diagnostics*. It is designed to be safe to share — it structurally cannot contain a
  credential, a device name or a user name, and you can read the whole thing before
  sending it. It does contain Microsoft request IDs, which are what actually lets a failure
  be traced.

## Security review

Commercial organizations are expressly permitted by the license to copy and read this
source to evaluate it, including running it in a test tenant. If you are doing that and have
questions, an Issue is fine for anything that is not a vulnerability. Things you are
welcome to try to break are listed in `SECURITY.md`; the network behavior you should expect
to observe is in `docs/NETWORK-TRANSPARENCY.md`.

## Roadmap

There is not a public roadmap yet. When there is, it will be built from Issues, curated by
hand, and it will never name who asked for what.
