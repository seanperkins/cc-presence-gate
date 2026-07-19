#!/bin/bash
# install/account-setup.sh — create the hidden _cctouchid service account (system-range uid, no login).
# The daemon (verify/custody) runs as this account; the agent uid cannot become it. Idempotent. Requires sudo.
#
# `sudo cc-touch-id install` (Sources/CCGateCore/Install.swift → MacOSPlatform.createServiceAccount)
# already creates this account as part of the normal install flow — this script exists as a standalone
# repair/inspection tool and for parity with the pre-subcommand install shape (see
# scripts/userrun/task7_install.sh's fork ancestor). Re-running it after `cc-touch-id install` is a
# harmless no-op (the account already exists).
set -eu
USERNAME=_cctouchid
if dscl . -read "/Users/$USERNAME" >/dev/null 2>&1; then
  echo "already exists: $USERNAME (uid $(id -u "$USERNAME"))"; exit 0
fi
# Pick a free uid in the 200-400 service range (highest used + 1).
UID_NEW=$(sudo dscl . -list /Users UniqueID | awk '$2>=200 && $2<400 {print $2}' | sort -n | tail -1)
UID_NEW=$(( ${UID_NEW:-299} + 1 ))
sudo dscl . -create "/Users/$USERNAME"
sudo dscl . -create "/Users/$USERNAME" UserShell /usr/bin/false
sudo dscl . -create "/Users/$USERNAME" RealName "cc-touch-id broker"
sudo dscl . -create "/Users/$USERNAME" UniqueID "$UID_NEW"
sudo dscl . -create "/Users/$USERNAME" PrimaryGroupID 20
sudo dscl . -create "/Users/$USERNAME" NFSHomeDirectory /var/empty
sudo dscl . -create "/Users/$USERNAME" IsHidden 1
echo "created: $USERNAME uid=$UID_NEW"
