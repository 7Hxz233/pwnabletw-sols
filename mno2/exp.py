from pwn import *


#  EAX  0x324f6e4d ◂— dec    eax /* 0x48484848; 'HHHHHHHH' */
#  EBX  0x0
#  ECX  0x0
#  EDX  0x8048890 ◂— dec    eax /* 'H' */
#  EDI  0xf7f36000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#  ESI  0xf7f36000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
#  EBP  0xff9b2e28 ◂— 0x0
# *ESP  0xff9b2dec —▸ 0x80487ea (main+169) ◂— mov    dword ptr [esp], 0
# *EIP  0x324f6e4d ◂— dec    eax /* 0x48484848; 'HHHHHHHH' */

context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

io = process("./mno2")

gdb.attach(io, "b *0x080487E8")

io.sendline("Ca")

io.interactive()