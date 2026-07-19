# Design: Notarized Developer-ID distribution of `cc-touch-id.app`

**Date:** 2026-07-19
**Status:** PROVEN on hardware (2026-07-19) + codified in `packaging/build-distribution.sh`.
The Developer-ID export produced a signature with `application-identifier` +
`keychain-access-groups`, no `get-task-allow`, embedded Developer ID profile; the SE
persist probe passed (no `-34018`); notarytool → Accepted; stapled; `spctl` accepted.
Residual: on-hardware `enroll` + a gated write under the *installed* notarized app.
**Goal (TID-5 distribution):** ship `cc-touch-id.app` so it runs on *any* Mac —
Gatekeeper-clean (notarized + stapled), hardened runtime, **`get-task-allow`
stripped** (not debuggable via same-uid `task_for_pid`), with the persistent
Secure Enclave key still working.

## Background — the blocker is real (empirically confirmed on macOS 26)

`docs/FOLLOWUPS.md` states notarized distribution is blocked because the SE-key
access group must be authorized by an embedded provisioning profile, and the only
available profile (Development wildcard) mandates `get-task-allow`, which is
incompatible with TID-5. **An earlier draft of this spec argued that was a
misdiagnosis. On-hardware probing (2026-07-19) proved the draft wrong and the
FOLLOWUPS right.** Three re-signs of the built `.app` (Developer ID cert, hardened
runtime, no embedded profile), each launched / SE-tested on the target Mac:

| Signature (Developer ID, no profile) | Launch | Persistent SE key |
|---|---|---|
| `keychain-access-groups` = `HH3SJBAS42.com.seanperkins.cc-touch-id` | **amfid SIGKILL (rc 137)** | — |
| **no entitlements** | launches ✅ | **`SecKeyCreateRandomKey` → -34018** `errSecMissingEntitlement` ("failed to add key to keychain") |

Conclusions, both now certain:
1. **A self-asserted `keychain-access-groups` is *not* accepted without a profile
   on macOS 26** — amfid kills the process at launch. (macOS behavior here is
   stricter than the old "team-prefixed groups are free on macOS" lore.)
2. **A persistent Secure-Enclave key cannot be stored without an authorized
   keychain access group.** With no entitlement the SE *generates* the key but
   macOS refuses to persist it (`-34018`). The enroller's `accessGroup: nil`
   needs a *default* group to exist, and none does without a profile.

You therefore cannot have both "launches" and "persists an SE key" from a bare
Developer ID signature. A **provisioning profile is required.**

## The fix — a Developer ID (`MAC_APP_DIRECT`) provisioning profile

The `-34018` shows the missing ingredient is an **authorized access group**. A
provisioning profile grants `application-identifier`
(= `HH3SJBAS42.com.seanperkins.cc-touch-id`) automatically, and that value *is*
the default group the enroller's `accessGroup: nil` resolves to. The Development
profile supplies this but forces `get-task-allow`. A **Developer ID** profile
(Apple profile type `MAC_APP_DIRECT`, for direct/notarized distribution) supplies
`application-identifier` **without** forcing `get-task-allow`.

So the working signature is: **Developer ID Application cert + hardened runtime +
embedded Developer ID provisioning profile + `keychain-access-groups` entitlement
(now authorized by the profile) + NO `get-task-allow`** → launches, persists the
SE key, notarizes, stays TID-5 attach-resistant.

**Open item (portal mechanics, not yet verified):** whether a `MAC_APP_DIRECT`
profile is self-serve for App ID `com.seanperkins.cc-touch-id`. Apple offers the
Developer ID profile type for App IDs carrying capabilities that *require*
provisioning; enabling **Keychain Sharing** on the App ID is the expected way to
make the entitlement provisioned (and to make the Developer ID profile
available). If the portal does not offer it, an Apple Developer support request
is the documented fallback. This is the one remaining unknown, and it is a
portal/entitlement question — the signing mechanics above are settled.

## Current-machine state (verified in the user's real shell)

- **notarytool profile `cc-touch-id-notary` exists and works.** `notarytool
  history` succeeds and shows a prior submission `b0f6ffaa-97ae-44e5-bf91-12efab22566c`
  (`cc-touch-id.app.zip`, 2026-07-19 03:10 UTC, **status Accepted**). ASC API key
  on disk: `~/Downloads/AuthKey_4XBH56T7RS.p8` (key id `4XBH56T7RS`).
- **A notarization has already been Accepted** — but that does NOT prove the
  artifact is distributable: notarytool accepts binaries that still carry
  `get-task-allow`, does not staple, and does not exercise the SE enroll. The
  accepted zip was not kept on disk and no `build-distribution.sh` exists, so its
  contents are unknown; `notarytool log <id>` is the way to see what was checked.
  Working hypothesis: an earlier run notarized the *author-machine* build (which
  already has hardened runtime + the Development profile + `get-task-allow`),
  which passes notarization but is not the TID-5 distribution artifact.
- **Signing identity state is NOT reliably known from this session.** Sandboxed
  `security find-identity` returned `0 valid identities`, but that probe runs
  under a keychain-restricted sandbox and gave a false negative on the notary
  profile too — so it cannot be trusted. The `Developer ID Application: Sean
  Perkins (HH3SJBAS42)` certificate IS visible in the login keychain, and a
  Developer-ID-signed zip was successfully produced for the accepted submission,
  which implies the private key was present at signing time. **Confirm in a real
  shell:** `security find-identity -v -p codesigning` should list one valid
  `Developer ID Application` identity. Only if it genuinely shows none does
  Section 1a (restore/recreate the identity) apply.

## Section 1 — Prerequisites (one-time)

### 1a. Developer ID Application signing identity

Confirm/obtain `Developer ID Application: … (HH3SJBAS42)` **with its private key**
in the login keychain.

- If a `.p12` export exists: `security import DeveloperID.p12 -k ~/Library/Keychains/login.keychain-db`.
- If not, create it (private key never leaves the machine):
  1. Keychain Access → Certificate Assistant → *Request a Certificate from a
     Certificate Authority* → "Saved to disk" → produces `CSR` + a new private
     key in the keychain.
  2. Apple Developer portal → Certificates → **Developer ID Application** →
     upload the CSR → download the `.cer` (or create via the App Store Connect
     API using the key we already have).
  3. Double-click the `.cer` to import; it pairs with the private key from step 1.
- **Gate:** `security find-identity -v -p codesigning` shows exactly one valid
  `Developer ID Application` identity.

### 1b. notarytool credential profile

A profile may **already exist** (user believes one is stored). Confirm before
creating a new one — the authoritative test is to use it:

```
xcrun notarytool history --keychain-profile "<existing-name>"
# a submission list (or empty history) → valid; "Must provide credentials" → not that name
```

If none exists, create one from the App Store Connect API key:

```
xcrun notarytool store-credentials "cc-touch-id-notary" \
  --key /path/AuthKey_<KID>.p8 --key-id <KID> --issuer <ISSUER_UUID>
```

Referenced later as `--keychain-profile "<name>"`. (`security dump-keychain`
does not reliably list these items non-interactively; don't rely on its absence
as proof a profile is missing.)

## Probe results (done — 2026-07-19, this session)

The interactive probing described above is complete; results are in the
Background table. Net: a bare Developer ID signature cannot both launch and
persist an SE key — a **Developer ID provisioning profile is required**. The
scratchpad throwaway `seprobe.swift` (persistent-SE-create test, bundle id
`com.seanperkins.cc-touch-id`, Developer ID + hardened runtime, no entitlement →
`-34018`) is the artifact that settled it.

## Section 2 — Build the distribution `.app` via Xcode automatic signing (USER-RUN)

Chosen route: **archive → export with `method: developer-id`**. The export step is
where Xcode automatic signing creates + embeds the Developer ID profile and strips
`get-task-allow`; a plain `xcodebuild build` cannot (it picks the Development
profile — the reason the current author-machine build carries `get-task-allow`).
`packaging/CCTouchID.entitlements` already asserts `keychain-access-groups`, and
`packaging/ExportOptions.plist` (`method: developer-id`, `signingStyle: automatic`)
drives the export.

### 2a. Archive + export

```
cd packaging
xcodegen generate         # or use the committed .xcodeproj
rm -rf .dd
xcodebuild -project CCTouchIDGate.xcodeproj -scheme cc-touch-id -configuration Release \
  -derivedDataPath .dd -allowProvisioningUpdates \
  archive -archivePath .dd/cc-touch-id.xcarchive

xcodebuild -exportArchive -archivePath .dd/cc-touch-id.xcarchive \
  -exportOptionsPlist ExportOptions.plist -exportPath .dd/export \
  -allowProvisioningUpdates
# → .dd/export/cc-touch-id.app  (Developer ID signed, Developer ID profile embedded)
```

`-allowProvisioningUpdates` lets Xcode enable **Keychain Sharing** on App ID
`com.seanperkins.cc-touch-id` and mint the Developer ID (`MAC_APP_DIRECT`) profile.
**If export fails** demanding an explicit App ID / capability, fall back to the
portal: create an *explicit* App ID `com.seanperkins.cc-touch-id` with Keychain
Sharing, generate a Developer ID profile, re-export. (The current build uses a
*wildcard* Development profile; Developer ID + keychain sharing needs an explicit
App ID — this is the most likely snag.)

### 2b. Verify the exported signature

```
APP=.dd/export/cc-touch-id.app
codesign -dvvv "$APP" 2>&1 | grep -iE 'Authority=|flags='   # Developer ID, flags=…(runtime)
codesign -d --entitlements :- "$APP"                        # keychain-access-groups present…
codesign -d --entitlements :- "$APP" | grep get-task-allow  # …and NO get-task-allow (empty)
[ -f "$APP/Contents/embedded.provisionprofile" ] && echo "profile embedded"
"$APP/Contents/MacOS/cc-touch-id" status --json             # launches (no amfid kill)
```

### 2c. On-hardware acceptance — persistent SE key + touch

With cc-touch-id installed/active on the machine, a real `enroll` (login user)
exercises `seCreateKey` (persistent) → export → register → positive-control
touch:

```
/path/to/cc-touch-id.app/Contents/MacOS/cc-touch-id enroll
```

**PASS:** SE key creates (no `-34018`), the positive-control touch signs and
verifies. → go to Section 3. **FAIL** (`-34018` persists): the embedded profile
did not authorize the access group — recheck the App ID capability / profile type
in 2a.

> NOTE: enrolling with a *temporary* build registers a key tied to that build's
> signature. Do the real enroll with the **installed** distribution app (same
> signature the daemon/hook use), not a throwaway copy, to avoid a key the
> installed binary can't reach.

## Section 3 — Notarize + staple + verify

```
ditto -c -k --keepParent cc-touch-id.app cc-touch-id.zip
xcrun notarytool submit cc-touch-id.zip \
  --keychain-profile "cc-touch-id-notary" --wait
# on Accepted:
xcrun stapler staple cc-touch-id.app
```

Verification gates (offline, simulating a fresh Mac):

```
spctl -a -vvv -t exec cc-touch-id.app     # → accepted, source=Notarized Developer ID
codesign -dvvv cc-touch-id.app 2>&1 | grep -E 'flags|Authority'   # runtime flag, Developer ID
codesign -d --entitlements - cc-touch-id.app | grep get-task-allow # → (no output)
stapler validate cc-touch-id.app          # → The validate action worked
```

If `notarytool submit` returns `Invalid`, `notarytool log <submission-id>
--keychain-profile …` gives the per-file reasons (common: a nested binary
missing hardened runtime, or a stray `get-task-allow`).

## Section 4 — Bake into the repo (after the path is confirmed)

- **`packaging/build-distribution.sh`** — new, separate from `build-signed.sh`.
  Builds Release → strips any embedded profile → direct `codesign` with
  `CCTouchID.distribution.entitlements` (runtime, timestamp, no get-task-allow)
  → self-verifies (signed, no profile, no get-task-allow, launches `status`) →
  notarize `--wait` → staple → `spctl`/`stapler` gates. `build-signed.sh` stays
  as the author-machine fallback for a machine without Developer ID.
- **`scripts/userrun/`** acceptance script — codifies the Section 2 + 3 hardware
  run (enroll + a real touch + notarize) as a USER-RUN step, since Claude cannot
  execute it.
- **`docs/FOLLOWUPS.md`** — correct the "needs a provisioning profile"
  entry to reflect the misdiagnosis and mark notarized distribution shipped
  (with the provisioning-profile route recorded as the contingency).

## Testing

- **[SW]** No new pure-logic surface; existing `swift test` unaffected. If
  `build-distribution.sh` grows any parsing/rendering helper, it goes in
  `CCGateCore`/`CLIHelpers` with a unit test, per repo convention.
- **[USER-RUN]** Section 2 probe (enroll under the distribution signature) and
  Section 3 notarize+staple+`spctl` gates are the acceptance evidence. No
  end-to-end claim is made until a USER-RUN run confirms it on hardware.

## Out of scope

- Distribution channel / installer packaging (`.dmg`/`.pkg`) beyond the stapled
  `.app` — the plugin install already places the `.app` at
  `/opt/cc-touch-id-gate/`.
- The `cc-fido` (FIDO) product's own signing; this spec is Touch ID only.
- Wiring the `ns` domain-separator (separate deferred followup).
