#!/bin/bash
# Start the server as _ccfido, connect as sean, confirm reachability + peer uid.
set -u
sudo cp task0-broker/probes/peercred_server.py /var/ccfido/peercred_server.py
sudo chown _ccfido /var/ccfido/peercred_server.py
sudo -u _ccfido /usr/bin/python3 /var/ccfido/peercred_server.py & SPID=$!
sleep 1
echo "=== connect as sean (uid $(id -u)) ==="
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/ccfido/gate.sock")
print("sean connected OK")
s.close()
PY
sleep 1; kill "$SPID" 2>/dev/null
