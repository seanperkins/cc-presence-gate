#!/bin/bash
# Start the server as _ccfido, connect as sean, confirm reachability + peer uid.
set -u
# Socket lives in a 0755 _ccfido-owned dir so sean can traverse to it (the keydir
# /var/ccfido is 0700 and deliberately unreachable — the socket must not live there).
sudo mkdir -p /var/ccfido-run
sudo chown _ccfido /var/ccfido-run
sudo chmod 755 /var/ccfido-run
sudo cp task0-broker/probes/peercred_server.py /var/ccfido-run/peercred_server.py
sudo chown _ccfido /var/ccfido-run/peercred_server.py
sudo -u _ccfido /usr/bin/python3 /var/ccfido-run/peercred_server.py & SPID=$!
sleep 1
echo "=== connect as sean (uid $(id -u)) ==="
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/ccfido-run/gate.sock")
print("sean connected OK")
s.close()
PY
sleep 1; kill "$SPID" 2>/dev/null
