#!/bin/bash
# Q3 — uchg file-lock + directory-lock enforcement against a same-machine agent uid.
# Uses root as a stand-in for the _ccfido owner; the owner-clears-uchg half is Task 4.
# Needs sudo for the privileged setup; cleans up after itself.
set -u
D=$(mktemp -d "${TMPDIR:-/tmp}/ccfg-q3.XXXXXX")
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; FAILED=1; }
FAILED=0

echo "=== FILE LOCK: root-owned + uchg file inside a sean-owned dir ==="
echo original > "$D/secret" 2>/dev/null
sudo chown root "$D/secret"
sudo chflags uchg "$D/secret"
ls -leO "$D/secret"

echo hostile > "$D/secret" 2>/dev/null && fail "sean WROTE the locked file" || pass "write -> denied"
rm -f "$D/secret" 2>/dev/null && fail "sean DELETED the locked file" || pass "unlink -> denied (immutable)"
mv "$D/secret" "$D/secret2" 2>/dev/null && fail "sean RENAMED the locked file" || pass "rename -> denied"
chflags nouchg "$D/secret" 2>/dev/null && fail "sean CLEARED uchg" || pass "chflags nouchg -> denied (not owner)"

echo "=== DIR LOCK: root-owned dir, mode 0755, sean cannot create ==="
sudo mkdir "$D/locked_dir"; sudo chown root "$D/locked_dir"; sudo chmod 755 "$D/locked_dir"
touch "$D/locked_dir/newfile" 2>/dev/null && fail "sean CREATED a file in the locked dir" || pass "create-in-dir -> denied"

echo
[ "$FAILED" = 0 ] && echo "RESULT: GREEN — uchg + dir-ownership lock out the agent uid" \
                  || echo "RESULT: RED — a lock leaked; file-custody guarantee does not hold"
echo "cleanup:"; sudo chflags nouchg "$D/secret" 2>/dev/null; sudo rm -rf "$D" && echo "  removed $D"
