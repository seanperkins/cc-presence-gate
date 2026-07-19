#!/bin/bash
# install/account-teardown.sh — remove the _cctouchid service account. Requires sudo. Safe to re-run.
# `sudo cc-touch-id uninstall` already does this as part of full teardown; this script is for
# standalone repair when you want to remove just the account without a full uninstall.
set -u
USERNAME=_cctouchid
sudo dscl . -delete "/Users/$USERNAME" 2>/dev/null && echo "deleted $USERNAME" || echo "$USERNAME not present"
