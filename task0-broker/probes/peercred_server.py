#!/usr/bin/env python3
# Bind a unix socket, accept one connection, read the peer uid via LOCAL_PEERCRED.
import socket, struct, sys, os
PATH = "/var/ccfido-run/gate.sock"  # dir is 0755 _ccfido-owned so sean can traverse to the socket
LOCAL_PEERCRED = 0x001  # macOS SO_PEERCRED equivalent option (xucred)
try:
    os.unlink(PATH)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(PATH)
os.chmod(PATH, 0o666)  # any local caller may connect; auth is by touch, not identity
s.listen(1)
print(f"listening on {PATH} as uid={os.getuid()}", flush=True)
conn, _ = s.accept()
# struct xucred: cr_version(u32), cr_uid(u32), cr_ngroups(short), cr_groups[16](u32)
xucred = conn.getsockopt(0, LOCAL_PEERCRED, 4 + 4 + 2 + 16 * 4)
cr_uid = struct.unpack("i", xucred[4:8])[0]
print(f"PEER uid={cr_uid}", flush=True)
conn.close()
